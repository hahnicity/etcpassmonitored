#!/usr/bin/env python
import imp
import os
import re

ETC_PASSWD_REGEX = (
    "(?P<username>[a-z\d_\-.]+):"
    "(?P<pw_placeholder>[\d\w]*):"
    "(?P<uid>\d+):"
    "(?P<gid>\d+):"
    "(?P<gecos>.*):"
    "(?P<homedir>[/\w \-]+):"
    "(?P<shell>[/\w ]+)"
)

ETC_SHADOW_REGEX = (
    "(?P<username>[a-z\d_\-.]+):"
    "(?P<encrypted_pw>.*):"
    "(?P<pw_change_date>\d+):"
    "(?P<min_days>\d*):"
    "(?P<max_days>\d*):"
    "(?P<warn_days>\d*):"
    "(?P<disabled_after_days>\d*):"
    "(?P<invalidate_days_after_expiration>\d*):"
    "(?P<expiration_date>\d*)"
)


def get_notify_func():
    if os.getenv("ETCPASSMONITORED_CONFIG"):
        config_path = os.getenv("ETCPASSMONITORED_CONFIG")
        if config_path[-3:] != ".py":
            raise Exception("Your config file needs to be a .py file!")
    else:
        config_path = os.path.join(os.path.dirname(__file__), "config.py")

    try:
        config = imp.load_source("config", config_path)
    except (IOError, SyntaxError):
        raise Exception(
            "There was a problem loading your config file < {} >. Please check to "
            "ensure your path is correct".format(config_path)
        )
    # It would be nice to just merge the default config with the new config. Don't
    # really have time to do that at the moment though so just error out if the
    # NOTFIY_MODULE property does not exist
    try:
        config.NOTIFY_MODULE
    except AttributeError:
        raise Exception("Your config module needs to set the NOTIFY_MODULE property")

    try:
        notify_module = imp.load_source("notify", config.NOTIFY_MODULE)
    except (IOError, SyntaxError):
        raise Exception(
            "There was a problem loading your notifications module < {} >. Please check "
            "to ensure the path is correct".format(config.NOTIFY_MODULE)
        )

    try:
        return notify_module.notify
    except AttributeError:
        raise Exception(
            "There was a problem loading the generic notification function to use "
            "please name it `notify`."
        )


def validate_etc_passwd(etcpasswd_lines, notify_func):
    parsed_etcpasswd = []
    for line in etcpasswd_lines:
        matched = re.search(ETC_PASSWD_REGEX, line)
        # There is something wrong with the line here. Notify about the failure
        if not matched:
            notify_func(
                "The line < {} > in /etc/passwd is incorrectly formatted"
                .format(line.rstrip("\n"))
            )
            continue
        parsed_etcpasswd.append(matched.groupdict())

        # Check for uids = 0 for logins other than root
        if parsed_etcpasswd[-1]["username"] != "root" and parsed_etcpasswd[-1]["uid"] == "0":
            notify_func(
                "User {} has uid 0. This is a potential security problem"
                .format(parsed_etcpasswd[-1]["username"])
            )

        # Ensure each user has a password placeholder.
        if parsed_etcpasswd[-1]["pw_placeholder"] == "":
            notify_func(
                "User {} has no password placeholder! This is a major security issue"
                .format(parsed_etcpasswd[-1]["username"])
            )

    # If there are users with the same uid then complain
    uid_mapping = {}
    for user_mapping in parsed_etcpasswd:
        # Search for users with overlapping uids besides root
        if user_mapping["uid"] in uid_mapping:
            uid_mapping[user_mapping["uid"]].append(user_mapping["username"])
        else:
            uid_mapping[user_mapping["uid"]] = [user_mapping["username"]]

    for uid, usernames in uid_mapping.iteritems():
        if len(usernames) > 1 and "root" not in usernames:
            notify_func(
                "Users {} have the same uid < {} >. This is a potential security problem"
                .format(",".join(usernames), uid)
            )

    return parsed_etcpasswd


def validate_etc_shadow(etcshadow_lines, notify_func):
    parsed_etcshadow = []
    for line in etcshadow_lines:
        matched = re.search(ETC_SHADOW_REGEX, line)
        if not matched:
            notify_func(
                "The line < {} > in /etc/shadow is incorrectly formatted"
                .format(line.rstrip("\n"))
            )
            continue
        parsed_etcshadow.append(matched.groupdict())
        if not parsed_etcshadow[-1]["encrypted_pw"]:
            notify_func(
                "The user {} has no password!"
                .format(parsed_etcshadow[-1]["username"])
            )
        if not parsed_etcshadow[-1]["expiration_date"]:
            notify_func(
                "The user {} has no expiration_date."
                .format(parsed_etcshadow[-1]["username"])
            )
    return parsed_etcshadow


def main():
    notify_func = get_notify_func()
    with open("/etc/passwd", "r") as etcpasswd:
        etcpasswd_lines = etcpasswd.readlines()
    validate_etc_passwd(etcpasswd_lines, notify_func)
    with open("/etc/shadow", "r") as etcshadow:
        etcshadow_lines = etcshadow.readlines()
    validate_etc_shadow(etcshadow_lines, notify_func)


if __name__ == "__main__":
    main()
