import requests
import string
import time
import re
import logging
import os
import random
import sqlite3
import asyncio
from onepassword import *
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler 
from apscheduler.triggers.cron import CronTrigger

# Configure logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, None)
if not isinstance(numeric_level, int):
	raise ValueError(f'Invalid log level: {log_level}')
logging.basicConfig(level=numeric_level, format='%(asctime)s - %(levelname)s - %(message)s')

class Computer:
	def __init__(self, id, name, management_id, recovery_password=None):
		self.id = id
		self.name = name
		self.management_id = management_id
		self.recovery_password = recovery_password
	
	def generateRandomPassword(self):
		logging.debug('Generating new password...')
		self.recovery_password = ''.join(random.SystemRandom().choice(string.ascii_uppercase) for _ in range(10))

class OnePasswordIntegration:
	def __init__(self):
		self.vault_id = os.getenv('VAULT_ID')
		self.auth = os.getenv('ONEPASSWORD_TOKEN')
	
	async def authenticate(self):
		self.client = await Client.authenticate(auth=self.auth, integration_name="SetRecoveryPassword", integration_version="1.0.0")

	async def create(self, computer, password):
		params = ItemCreateParams(
			title=f'{computer.name} ({computer.id}) - Recovery Password',
			category=ItemCategory.PASSWORD,
			vault_id=self.vault_id,
			fields=[
				ItemField(
					id="password",
					title="password",
					field_type=ItemFieldType.CONCEALED,
					value=password
				)
			]
		)

		created_item = await self.client.items.create(params)
		return created_item.id

	async def update(self, uuid, password):
		item = await self.client.items.get(self.vault_id, uuid)
		item.field[0].value = password
		await self.client.items.put(item)


class StateDatabase:
	def __init__(self):
		self._database = sqlite3.connect('/config/state.db')
		self.cursor = self._database.cursor()
		self.cursor.execute('''
					  CREATE TABLE IF NOT EXISTS state (
					  id INTEGER PRIMARY KEY,
					  password TEXT,
					  password_uuid TEXT,
					  date TEXT NOT NULL
					  );
		''')
	
	def reinit(self):
		self._database = sqlite3.connect('/config/state.db')
		self.cursor = self._database.cursor()

	def get_all(self):
		rows = self.cursor.execute("SELECT id, password, password_uuid, date FROM state").fetchall()
		if len(rows) == 0:
			return None
		else:
			return rows
	
	def get(self, computer):
		password, date = self.cursor.execute('SELECT password, date FROM state WHERE id = ?', (computer.id,)).fetchone()
		return (password, date)

	def get_uuid(self, computer):
		password_uuid, = self.cursor.execute('SELECT password_uuid FROM state WHERE id = ?', (computer.id,)).fetchone()
		return password_uuid
		
	def create(self, computer):
		self.cursor.execute('INSERT INTO state (id, password, date) VALUES (?, ?, ?)', (computer.id, computer.recovery_password, datetime.today().timestamp()))
		self._database.commit()

	def update(self, computer):
		self.cursor.execute('UPDATE state SET password = ?, date = ? WHERE id = ?', (computer.recovery_password, datetime.today().timestamp(), computer.id))	
		self._database.commit()

	def touch(self, computer):
		self.cursor.execute('UPDATE state SET date = ? WHERE id = ?', (datetime.today().timestamp(), computer.id))
		self._database.commit()

	def migrate(self, computer, password_uuid):
		self.cursor.execute('UPDATE state SET password = \'\', password_uuid = ? WHERE id = ?', (password_uuid, computer.id))
		self._database.commit()

	def close(self):
		self._database.commit()
		self.cursor.close()
		self._database.close()

class SetRecoveryLock:
	def __init__(self, jamf_host, jamf_client_id, jamf_client_secret, dry_run):
		self.jamf_host = jamf_host
		self.jamf_client_id = jamf_client_id
		self.jamf_client_secret = jamf_client_secret
		self.dry_run = dry_run
		self.onePassword = OnePasswordIntegration()
		self.database = StateDatabase()
		self.__authenticate_jamf_API__()
		logging.info('Initiliazed service')

	def __authenticate_jamf_API__(self):
		logging.debug('Authenticating to Jamf API...')
		headers = {'Content-Type': 'application/x-www-form-urlencoded'}
		data = {
			'client_id': self.jamf_client_id,
			'client_secret': self.jamf_client_secret,
			'grant_type': 'client_credentials'
		}
		response = requests.post(f'https://{self.jamf_host}/api/oauth/token', headers=headers, data=data)
		response.raise_for_status()
		self.jamf_access_token = response.json()['access_token']
		self.jamf_token_expiry = datetime.now(timezone.utc) + timedelta(seconds=response.json()['expires_in'])
		logging.debug('Successfully retrieved an access token')
	
	def __check_token__(self):
		logging.debug('Checking access token expiry...')
		if datetime.now(timezone.utc) >= self.jamf_token_expiry - timedelta(seconds=10):
			logging.info('Access token expired, re-authenticating...')
			self.__authenticate_jamf_API__()
		else:
			logging.debug('Access token fine')
	
	def __check_cursor__(self):
		logging.debug('Checking if local database cursor is still available...')
		try:
			logging.debug('Cursor fine')
			self.database.get_all()
		except sqlite3.ProgrammingError:
			logging.debug('Cursor object closed, creating new...')
			self.database.reinit()
	
	async def __auth_onepassword__(self):
		await self.onePassword.authenticate()
	
	def getAllmacOSDevices(self):
		self.__check_token__()

		logging.info('Getting all macOS devices from Jamf...')
		devices = []

		headers = {
			'Accept': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}

		query = {
			'section': [
				'GENERAL'
			],
			'page-size': 5000,
			'filter': 'general.remoteManagement.managed==true'
		}

		response = requests.get(f'https://{self.jamf_host}/api/v1/computers-inventory', params=query, headers=headers)
		response.raise_for_status()

		for device in response.json()['results']:
			computer = Computer(device['id'], device['general']['name'], device['general']['managementId'])
			devices.append(computer)
		
		return devices
	
	def getCurrentRecoveryPassword(self, computer):
		self.__check_token__()

		logging.debug(f'Getting current recovery lock password for computer {computer.id}')

		headers = {
			'Accept': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}

		response = requests.get(f'https://{self.jamf_host}/api/v1/computers-inventory/{computer.id}/view-recovery-lock-password', headers=headers)
		if response.status_code == 404:
			return None
		else:
			response.raise_for_status()
			return response.json()['recoveryLockPassword']


	def setNewRecoveryPassword(self, computer):
		self.__check_token__()

		logging.debug(f'Setting new recovery lock password for computer {computer.id}')

		headers = {
			'Content-Type': 'application/json',
			'Authorization': f'Bearer {self.jamf_access_token}'
		}

		payload = {
			'clientData': [
				{
					'managementId': computer.management_id
				}
			],
			'commandData': {
				'commandType': 'SET_RECOVERY_LOCK',
				'newPassword': computer.recovery_password
			}
		}

		if not self.dry_run:
			response = requests.post(f'https://{self.jamf_host}/api/v2/mdm/commands', headers=headers, json=payload)
			response.raise_for_status()
			logging.info(f'Recovery password set for computer {computer.id} successfully')
		else:
			logging.debug(f'DRY RUN: Would have set password for {computer.name} to {computer.recovery_password}')

	async def moveFromDatabaseToOnePassword(self, computer, password):
		self.__check_cursor__()

		if (uuid := self.database.get_uuid(computer)) is not None:
			await self.onePassword.update(uuid, password)
		else:
			uuid = await self.onePassword.create(computer, password)
		self.database.migrate(computer, uuid)

	async def update(self):
		self.__check_token__()
		self.__check_cursor__()
		await self.__auth_onepassword__()

		devices = self.getAllmacOSDevices()

		for device in devices:
			try:
				logging.debug(f'Getting information for {device.id} from local database')
				password, date = self.database.get(device)
				if password != None:
					logging.debug(f'Password for {device.id} is still in database, comparing to one in Jamf...')
					jamf_recovery_password = self.getCurrentRecoveryPassword(device)
					if jamf_recovery_password == None:
						logging.debug(f'No password stored in Jamf for {device.id}, extending expiration until the password appears in the record...')
						self.database.touch(device)
					elif jamf_recovery_password != password:
						logging.debug(f'Password for {device.id} is different to one in Jamf, extending expiration until they match')
						self.database.touch(device)
					else:
						logging.debug(f'Password for {device.id} matches Jamf\'s, moving password from local database into 1Password')
						await self.moveFromDatabaseToOnePassword(device, password)
				elif date < datetime.now(timezone.utc) - timedelta(days=31):
					logging.info(f'Password for {device.id} has expired, setting new one...')
					device.generateRandomPassword()
					self.setNewRecoveryPassword(device)
					self.database.update(device)
			except TypeError:
				logging.info(f'No record in local database for {device.id}, setting new password and creating record...')
				device.generateRandomPassword()
				self.setNewRecoveryPassword(device)
				self.database.create(device)
		
		self.database.close()
	
async def main():
	logging.info('Script started')
	jamf_client_id = os.getenv('JAMF_CLIENT_ID', '')
	jamf_client_secret = os.getenv('JAMF_CLIENT_SECRET', '')
	jamf_host = os.getenv('JAMF_HOST')
	update_now = os.getenv('UPDATE_NOW', 'false').lower() == 'true'
	dry_run = os.getenv('DRY_RUN', 'false').lower() == 'true'
	update = SetRecoveryLock(jamf_host, jamf_client_id, jamf_client_secret, dry_run)
	if update_now:
		logging.info('Running update immediately due to UPDATE_NOW setting')
		await update.update()
	cron_schedule = os.getenv('UPDATE_SCHEDULE', '0 0 * * *')
	scheduler = AsyncIOScheduler()
	scheduler.add_job(update.update, CronTrigger.from_crontab(cron_schedule))
	scheduler.start()
	logging.info(f'Scheduled update with cron: {cron_schedule}')
	try:
		while True:
			await asyncio.sleep(10)
	except (KeyboardInterrupt, SystemExit):
		logging.info('Scheduler shutdown initiated')
		scheduler.shutdown()

if __name__ == '__main__':
	loop = asyncio.get_event_loop()
	loop.create_task(main())
	loop.run_forever()