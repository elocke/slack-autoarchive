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

load_dotenv()


class ChannelReaper:
    """
    This class can be used to archive slack channels.
    """

    def __init__(self):
        self.settings = get_channel_reaper_settings()
        self.logger = get_logger("channel_reaper", "./audit.log")

    def get_whitelist_keywords(self):
        """
        Get all whitelist keywords. If this word is used in the channel
        purpose or topic, this will make the channel exempt from archiving.
        """
        keywords = []
        if os.path.isfile("whitelist.txt"):
            with open("whitelist.txt") as filecontent:
                keywords = filecontent.readlines()

        # remove whitespace characters like `\n` at the end of each line
        keywords = map(lambda x: x.strip(), keywords)
        whitelist_keywords = self.settings.get("whitelist_keywords")
        if whitelist_keywords:
            keywords = keywords + whitelist_keywords.split(",")
        return list(keywords)

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
            self.logger.error(f"Need to setup auth. eg, BOT_SLACK_TOKEN=<secret token> " f"python slack-autoarchive.py")
            sys.exit(1)

        return response.json()

    def get_all_users(self):
        """Get a list of all users from slack users.list."""
        payload = {}
        api_endpoint = "users.list"

        users = []
        resp = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)
        users.extend(resp["members"])

        while resp.get("response_metadata"):
            metadata = resp.get("response_metadata")
            if metadata.get("next_cursor"):
                payload["cursor"] = metadata.get("next_cursor")
                resp = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)
                users.extend(resp["members"])
            else:
                break

        all_users = {}
        for user in users:
            if not user["is_bot"]:
                all_users[user["id"]] = {"name": user["name"], "realname": user["real_name"]}
        return all_users

    def get_all_channels(self):
        """Get a list of all non-archived channels from slack channels.list."""
        payload = {"exclude_archived": 1, "types": "public_channel,private_channel"}
        api_endpoint = "conversations.list"

        channels = []
        resp = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)
        channels.extend(resp["channels"])

        while resp.get("response_metadata"):
            metadata = resp.get("response_metadata")
            if metadata.get("next_cursor"):
                payload["cursor"] = metadata.get("next_cursor")
                resp = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)
                channels.extend(resp["channels"])
            else:
                break

        users = self.get_all_users()

        all_channels = []
        for channel in channels:
            self.logger.info(f'Checking if the bot is in #{channel["name"]}...')
            if not channel["is_member"]:
                self.join_channel(channel)
            channel_history = self.get_channel_history(channel)
            latest_timestamp = self.get_last_message_timestamp(channel_history, self.settings.get("too_old_datetime"))
            info_payload = {"channel": channel["id"]}
            channel_info = self.slack_api_http(api_endpoint="conversations.info", payload=info_payload, method="GET")
            channel_info = channel_info["channel"]
            creator_name = users[channel["creator"]]["name"]
            creator_realname = users[channel["creator"]]["realname"]

            all_channels.append(
                {
                    "id": channel["id"],
                    "name": channel["name"],
                    "created": channel["created"],
                    "num_members": channel["num_members"],
                    "is_member": channel["is_member"],
                    "previous_names": channel_info["previous_names"] if "previous_names" in channel_info else "",
                    "topic": channel_info["topic"],
                    "purpose": channel_info["purpose"],
                    "creator": channel_info["creator"],
                    "creator_name": creator_name,
                    "creator_realname": creator_realname,
                    "archived": channel_info["is_archived"],
                    "is_private": channel_info["is_private"],
                    "is_shared": channel_info["is_shared"],
                    "last_message_timestamp": {"timestamp": latest_timestamp[0], "is_user": latest_timestamp[1]},
                }
            )

        return all_channels

    def get_channel_history(self, channel):
        payload = {"inclusive": 0, "oldest": 0, "limit": 50}
        api_endpoint = "conversations.history"

        payload["channel"] = channel["id"]
        channel_history = self.slack_api_http(api_endpoint=api_endpoint, payload=payload)

        return channel_history

    def get_last_message_timestamp(self, channel_history, too_old_datetime):
        """Get the last message from a slack channel, and return the time."""
        last_message_datetime = too_old_datetime
        last_bot_message_datetime = too_old_datetime

        if "messages" not in channel_history:
            return (last_message_datetime, False)  # no messages

        for message in channel_history["messages"]:
            if "subtype" in message and message["subtype"] in self.settings.get("skip_subtypes"):
                continue
            last_message_datetime = datetime.fromtimestamp(float(message["ts"]))
            break
        # for folks with the free plan, sometimes there is no last message,
        # then just set last_message_datetime to epoch
        if not last_message_datetime:
            last_bot_message_datetime = datetime.utcfromtimestamp(0)
        # return bot message time if there was no user message
        if too_old_datetime >= last_bot_message_datetime > too_old_datetime:
            return (last_bot_message_datetime, False)
        return (last_message_datetime, True)

    def is_channel_disused(self, channel, too_old_datetime):
        """Return True or False depending on if a channel is "active" or not."""
        num_members = channel["num_members"]
        last_message_datetime = channel["last_message_timestamp"]["timestamp"]
        is_user = channel["last_message_timestamp"]["is_user"]

        # mark inactive if last message is too old, but don't
        # if there have been bot messages and the channel has
        # at least the minimum number of members
        min_members = self.settings.get("min_members")
        has_min_users = min_members == 0 or min_members > num_members
        return last_message_datetime <= too_old_datetime and (not is_user or has_min_users)

    # If you add channels to the WHITELIST_KEYWORDS constant they will be exempt from archiving.
    def is_channel_whitelisted(self, channel, white_listed_channels):
        """Return True or False depending on if a channel is exempt from being archived."""
        # self.settings.get('skip_channel_str')
        # if the channel purpose contains the string self.settings.get('skip_channel_str'), we'll skip it.

        channel_purpose = channel["purpose"]["value"]
        channel_topic = channel["topic"]["value"]
        if (
            self.settings.get("skip_channel_str") in channel_purpose
            or self.settings.get("skip_channel_str") in channel_topic
        ):
            return True

        # check the white listed channels (file / env)
        for white_listed_channel in white_listed_channels:
            wl_channel_name = white_listed_channel.strip("#")
            if wl_channel_name in channel["name"]:
                return True
        return False

    def send_channel_message(self, channel_id, message):
        """Send a message to a channel or user."""
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

    def join_channel(self, channel):
        """Joins a channel so that the bot can read the last message."""
        if not self.settings.get("dry_run"):
            self.logger.info(f'Adding bot to #{channel["name"]}')
            join_api_endpoint = "conversations.join"
            join_payload = {"channel": channel["id"]}
            channel_info = self.slack_api_http(api_endpoint=join_api_endpoint, payload=join_payload)
        else:
            self.logger.info(f'THIS IS A DRY RUN. BOT would have joined {channel["name"]}')

    def send_admin_report(self, channels):
        """Optionally this will message admins with which channels were archived."""
        if self.settings.get("admin_channel"):
            channel_names = ", ".join("#" + channel["name"] for channel in channels)
            admin_msg = f"Archiving {len(channels)} channels: {channel_names}"

            if self.settings.get("dry_run"):
                admin_msg = f"[DRY RUN] {admin_msg}"
            self.send_channel_message(self.settings.get("admin_channel"), admin_msg)

    def csv_report(self, channels):
        csv_file = self.settings.get("reportfile", "report.csv")
        report_dict = []
        for chan in channels:
            report_dict.append(
                {
                    "archived": chan["archived"],
                    "created": datetime.fromtimestamp(chan["created"]).strftime("%x %X"),
                    "creator_name": chan["creator_name"],
                    "creator_realname": chan["creator_realname"],
                    "id": chan["id"],
                    "is_disused": chan["is_disused"] if "is_disused" in chan else "",
                    "is_member": chan["is_member"],
                    "is_private": chan["is_private"],
                    "is_shared": chan["is_shared"],
                    "is_whitelisted": chan["is_whitelisted"] if "is_disused" in chan else "",
                    "last_message_timestamp": chan["last_message_timestamp"]["timestamp"].strftime("%x %X"),
                    "name": chan["name"],
                    "num_members": chan["num_members"],
                    "previous_names": ", ".join(chan["previous_names"]),
                    "purpose": chan["purpose"]["value"],
                    "topic": chan["topic"]["value"],
                }
            )

        headers = [
            "id",
            "name",
            "creator_name",
            "creator_realname",
            "created",
            "last_message_timestamp",
            "num_members",
            "topic",
            "purpose",
            "archived",
            "previous_names",
            "is_member",
            "is_private",
            "is_shared",
            "is_whitelisted",
            "is_disused",
        ]
        with open(csv_file, "w") as output_file:
            dict_writer = csv.DictWriter(output_file, restval="-", fieldnames=headers, delimiter="@")
            dict_writer.writeheader()
            dict_writer.writerows(report_dict)

    def main(self):
        """
        This is the main method that checks all inactive channels and archives them.
        """
        if self.settings.get("dry_run"):
            self.logger.info("THIS IS A DRY RUN. NO CHANNELS ARE ACTUALLY ARCHIVED.")

        whitelist_keywords = self.get_whitelist_keywords()
        archived_channels = []

        self.logger.info(
            f"Graabing a list of all channels. " f"This could take a moment depending on the number of channels."
        )

        channels = self.get_all_channels()

        for channel in channels:
            if channel["is_member"]:
                channel["is_whitelisted"] = self.is_channel_whitelisted(channel, whitelist_keywords)
                channel["is_disused"] = self.is_channel_disused(channel, self.settings.get("too_old_datetime"))

                if not channel["is_whitelisted"] and channel["is_disused"]:
                    channels["archive_candidate"] = True
                    archived_channels.append(channel)
                    self.archive_channel(channel)

        self.send_admin_report(archived_channels)
        self.csv_report(channels)


if __name__ == "__main__":
    CHANNEL_REAPER = ChannelReaper()
    CHANNEL_REAPER.main()
