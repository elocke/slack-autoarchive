#!/usr/bin/env python
"""
This program lets you do archive slack channels which are no longer active.
"""

# standard imports
from datetime import datetime
import os
import sys
import time
import json
from pprint import pprint
import csv

# not standard imports
import requests
from config import get_channel_reaper_settings
from utils import get_logger
from dotenv import load_dotenv
from channels_to_delete import stale_eng_and_prod, gt180_lt4_channels, old_epoch_channels, lunch_round

load_dotenv()


class ChannelReaper:
    """
    This class can be used to archive slack channels.
    """

    def __init__(self):
        self.settings = get_channel_reaper_settings()
        self.logger = get_logger("channel_reaper", "./auditmanual.log")

    def slack_api_http(self, api_endpoint=None, payload=None, method="GET"):
        """Helper function to query the slack api and handle errors and rate limit."""
        uri = f"https://slack.com/api/{api_endpoint}"
        header = {"Authorization": f'Bearer {self.settings.get("bot_slack_token")}'}
        try:
            if method == "POST":
                response = requests.post(uri, headers=header, data=payload)
            else:
                response = requests.get(uri, headers=header, params=payload)

        except requests.exceptions.RequestException as e:
            # TODO: Do something more interesting here?
            raise SystemExit(e)

        if response.status_code == requests.codes.too_many_requests:
            timeout = int(response.headers["retry-after"]) + 3
            self.logger.info(f"rate-limited: Trying again in {timeout} seconds.")
            time.sleep(timeout)
            return self.slack_api_http(api_endpoint, payload, method)

        if response.status_code == requests.codes.ok and response.json().get("error", False) == "not_authed":
            self.logger.error(
                f"Need to setup auth. eg, BOT_SLACK_TOKEN=<secret token> " f"python slack-autoarchive.py"
            )
            sys.exit(1)

        return response.json()

    def send_channel_message(self, channel_id, message):
        """Send a message to a channel or user."""
        self.logger.info(f"Would have posted a {message} to ${channel_id}")
        payload = {"channel": channel_id, "text": message}
        api_endpoint = "chat.postMessage"
        self.slack_api_http(api_endpoint=api_endpoint, payload=payload, method="POST")

    def archive_channel(self, channel):
        """Archive a channel, and send alert to slack admins."""
        api_endpoint = "conversations.archive"

        if not self.settings.get("dry_run"):
            self.logger.info(f'Archiving channel #{channel["name"]}')
            payload = {"channel": channel["id"]}
            resp = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)
            if not resp.get("ok"):
                stdout_message = f'Error archiving #{channel["name"]}: ' f'{resp["error"]}'
                self.logger.error(stdout_message)
        else:
            self.logger.info(f"THIS IS A DRY RUN. " f'{channel["name"]} would have been archived.')

    def send_admin_report(self, channels):
        """Optionally this will message admins with which channels were archived."""
        if self.settings.get("admin_channel"):
            channel_names = ", ".join("#" + channel["name"] for channel in channels)
            admin_msg = f"Archiving {len(channels)} channels: {channel_names}"

            if self.settings.get("dry_run"):
                admin_msg = f"[DRY RUN] {admin_msg}"
            self.send_channel_message(self.settings.get("admin_channel"), admin_msg)

    def main(self):
        """
        This is the main method that checks all inactive channels and archives them.
        """
        if self.settings.get("dry_run"):
            self.logger.info("THIS IS A DRY RUN. NO CHANNELS ARE ACTUALLY ARCHIVED.")

        archived_channels = []

        self.logger.info(
            f"Graabing a list of all channels. " f"This could take a moment depending on the number of channels."
        )

        for channel in lunch_round:
            archived_channels.append(channel)
            self.archive_channel(channel)

        self.send_admin_report(archived_channels)


if __name__ == "__main__":
    CHANNEL_REAPER = ChannelReaper()
    CHANNEL_REAPER.main()
