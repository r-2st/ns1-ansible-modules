#!/usr/bin/python

# Copyright: (c) 2021, NS1
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ns1_user

short_description: Create, modify and delete NS1 user accounts.

version_added: "3.1"

description:
  - Create, modify and delete user objects along with permissions and team membership.

options:
  2fa_enabled:
    description: Whether require 2FA on user login. Defaults to false
    required: false
    type: bool
  apiKey:
    description: Unique client api key that can be created via the NS1 portal.
    required: true
    type: str
  email:
    description: (Required when creating) Email address associated with the new user. This is where the invite email and other notifications, if applicable, are sent.
    required: true
    type: str
  endpoint:
    description: NS1 API endpoint. Defaults to https://api.nsone.net/v1/
    required: false
    type: str
  ignore_ssl:
    description: Whether to ignore SSL errors. Defaults to false
    required: false
    type: bool
  ip_whitelist_strict:
    description: Set to true to restrict access to only those IP addresses and networks listed in the ip_whitelist field.
    required: false
    type: bool
  ip_whitelist:
    description: Array of IP addresses/networks to which to grant the API key access.
    required: false
    type: list
  name:
    description: Full name of the new user.
    required: true
    type: str
  notify:
    default: None
    description: Set of supported notifications to enable or disable for this user.
    required: false
    suboptions:
      billing:
        description: (part of notify object) Enables or disables notifications related to account billing events.
        type: bool
        default: false
        required: false
  permissions:
    default: None
    description: All supported permissions
    required: false
    suboptions:
      account:
        description: Group of account-related permissions.
        required: false
        suboptions:
          manage_account_settings:
            description: Allows (or prevents, if false) the user to manage account settings.
            type: bool
            default: false
            required: false
          manage_apikeys:
            description: Allows (or prevents, if false) the user to create or update API keys.
            type: bool
            default: false
            required: false
          manage_ip_whitelist:
            description: Allows (or prevents, if false) the user to create or update IP "allow" lists.
            type: bool
            default: false
            required: false
          manage_payment_methods:
            description: Allows (or prevents, if false) the user to manage account payment methods.
            type: bool
            default: false
            required: false
          manage_plan:
            description: Allows (or prevents, if false) the user to manage account plans.
            type: bool
            default: false
            required: false
          manage_users:
            description: Allows (or prevents, if false) the user to create or update users.
            type: bool
            default: false
            required: false
          manage_users:
            description: Allows (or prevents, if false) the user to create or update users.
            type: bool
            default: false
            required: false
          view_activity_log:
            description: Allows (or prevents, if false) the user to view the account activity log.
            type: bool
            default: false
            required: false
          view_invoices:
            description: Allows (or prevents, if false) the user to view account invoices.
            type: bool
            default: false
            required: false
      data:
        description: Group of data-related permissions.
        required: false
        suboptions:
          manage_datafeeds:
            description: Allows (or prevents, if false) the user to create and modify data feeds.
            type: bool
            default: false
            required: false
          manage_datasources:
            description: Allows (or prevents, if false) the user to create and modify data sources.
            type: bool
            default: false
            required: false
          push_to_datafeeds:
            description: Allows (or prevents, if false) the user to push data to NS1 data feeds.
            type: bool
            default: false
            required: false
      dns:
        description: Group of DNS-related permissions.
        required: false
        suboptions:
          manage_zones:
            default: false
            description:  Allows (or prevents, if false) the user to create or modify zones.
            required: false
            type: bool
          view_zones:
            default: false
            description: Allows (or prevents, if false) the user to view zones.
            required: false
            type: bool
          zones_allow_by_default:
            default: false
            description: Set to true to allow access to all zones except for those listed under zones_deny. Set to false to deny access to all zones by default except for those listed under zones_allow.
            required: false
            type: bool
          zones_allow:
            description: List of specific zones to which the API key is allowed access.
            required: false
            type: list
          zones_deny:
            description: List of specific zones to which the user is denied access.
            required: false
            type: list
      monitoring:
        description: Group of monitoring-related permissions.
        required: false
        suboptions:
          manage_jobs:
            description: Allows (or prevents, if false) the user to create or modify monitoring jobs.
            type: bool
            default: false
            required: false
          manage_lists:
            description: Allows (or prevents, if false) the user to create or modify notification lists.
            type: bool
            default: false
            required: false
          view_jobs:
            description: Allows (or prevents, if false) the user to view monitoring jobs.
            type: bool
            default: false
            required: false
      security:
        description: Group of security-related permissions.
        required: false
        suboptions:
          manage_global_2fa:
            description: Allows (or prevents, if false) the user to manage global two-factor authentication (2FA) settings.
            type: bool
            default: false
            required: false
    type: dict
  state:
    choices:
      - absent
      - present
    default: present
    description: Whether the user should be present or not.  Use C(present) to create or update and C(absent) to delete.
    required: false
    type: str
  teams:
    description: Array of team IDs corresponding to teams with which to associate this user. If assigned to a team, the user inherits the permissions set for that team.
    required: false
    type: list
  username:
    description: (Required) Username for the new account user. Must be between 3-64 characters.
    required: true
    type: str

requirements:
  - ns1-python >= 0.16.0
  - python >= 2.7

seealso:
  - name: Documentation for NS1 API
    description: Complete reference for the NS1 API.
    link: https://ns1.com/api/

author:
  - 'NS1'
"""

EXAMPLES = r"""
- name: add read only user
  local_action:
    module: ns1_user
    email: dns.admin@ns1.com
    permissions:
      account:
        view_activity_log: true
        view_invoices: true
      dns:
        view_zones: true
      monitoring:
        view_jobs: true
    state: present
    teams:
        - 23dffe14c7ee11eba218acde
        - ada2912991a5403499fdc64f
    username: dns.admin

- name: delete user
  local_action:
    apiKey: "{{ ns1_token }}"
    module: ns1_user
    username: NoLongerAdmin
    state: absent
"""

RETURN = r"""
"""

import functools  # noqa
import copy

try:
    from ansible.module_utils.ns1 import NS1ModuleBase, HAS_NS1, Decorators
except ImportError:
    # import via absolute path when running via pytest
    from module_utils.ns1 import NS1ModuleBase, HAS_NS1, Decorators  # noqa

try:
    from ns1.rest.errors import ResourceException
    from ns1.rest.permissions import _default_perms
except ImportError:
    # This is handled in NS1 module_utils
    pass


class NS1user(NS1ModuleBase):
    """Represents the NS1 user module implementation"""

    def __init__(self):
        """Constructor method"""
        self.module_arg_spec = dict(
            two_fa_enabled=dict(required=False, type="bool", default=False),
            email=dict(required=False, type="str"),
            ip_whitelist_strict=dict(required=False, type="bool", default=False),
            ip_whitelist=dict(required=False, type="list", default=None),
            name=dict(required=False, type="str"),
            notify=dict(
                default=None,
                options=dict(
                    billing=dict(type="bool", default=False),
                ),
                required=False,
                type="dict",
            ),
            permissions=dict(
                default=None,
                options=dict(
                    account=dict(
                        default=None,
                        options=dict(
                            manage_account_settings=dict(type="bool", default=False),
                            manage_apikeys=dict(type="bool", default=False),
                            manage_ip_whitelist=dict(type="bool", default=False),
                            manage_payment_methods=dict(type="bool", default=False),
                            manage_plan=dict(type="bool", default=False),
                            manage_teams=dict(type="bool", default=False),
                            manage_users=dict(type="bool", default=False),
                            view_activity_log=dict(type="bool", default=False),
                            view_invoices=dict(type="bool", default=False),
                        ),
                        required=False,
                        type="dict",
                    ),
                    data=dict(
                        default=None,
                        options=dict(
                            manage_datafeeds=dict(type="bool", default=False),
                            manage_datasources=dict(type="bool", default=False),
                            push_to_datafeeds=dict(type="bool", default=False),
                        ),
                        required=False,
                        type="dict",
                    ),
                    dns=dict(
                        default=None,
                        options=dict(
                            manage_zones=dict(type="bool", default=False),
                            view_zones=dict(type="bool", default=False),
                            zones_allow_by_default=dict(type="bool", default=False),
                            zones_allow=dict(type="list", default=[]),
                            zones_deny=dict(type="list", default=[]),
                        ),
                        required=False,
                        type="dict",
                    ),
                    monitoring=dict(
                        default=None,
                        options=dict(
                            manage_jobs=dict(type="bool", default=False),
                            manage_lists=dict(type="bool", default=False),
                            view_jobs=dict(type="bool", default=False),
                        ),
                        required=False,
                        type="dict",
                    ),
                    security=dict(
                        default=None,
                        options=dict(
                            manage_global_2fa=dict(type="bool", default=False),
                        ),
                        required=False,
                        type="dict",
                    ),
                ),
                required=False,
                type="dict",
            ),
            state=dict(
                choices=["present", "absent"],
                default="present",
                required=False,
                type="str",
            ),
            teams=dict(required=False, type="list", default=None),
            username=dict(required=True, type="str"),
        )

        NS1ModuleBase.__init__(
            self,
            self.module_arg_spec,
            supports_check_mode=True,
        )

    @Decorators.skip_in_check_mode
    def update(self, built_changes):
        """Updates a user with permissions from task

        :param username: user object of existing user returned by NS1.
        :type username: str
        :param built_changes: Dict of permissions to be applied to a new.
        user.
        :type built_changes: dict
        :return: The updated user object returned by NS1.
        :rtype: dict
        """
        user_update = self.ns1.user()
        return user_update.update(**built_changes)

    @Decorators.skip_in_check_mode
    def create(self, built_changes):
        """Creates a user with the given permissions.

        :param built_changes: Dict of permissions to be applied to a new
        user.
        :type built_changes: dict
        :return: The created user object returned by NS1.
        :rtype: dict
        """
        user_create = self.ns1.user()
        return user_create.create(**built_changes)

    @Decorators.skip_in_check_mode
    def delete(self, username):
        """Deletes a user.

        :param username: existing user.
        :type username: str
        """
        user_delete = self.ns1.user()
        user_delete.delete(username)

    def build_notify(self):
        """Builds a list of dicts modeled to be the same as the API call.

        :return: A list of dicts
        :rtype: list
        """
        built_notify = dict(notify={"billing": False})
        if self.module.params["notify"] is not None:
            built_notify["notify"]["billing"] = self.module.params["notify"]["billing"]
        return built_notify

    def build_email(self, before, email, username):
        """Builds an email address. Can return a NoneType for use in later
        checks

        :param email: Passed in email address
        :type email: str
        :return: An email or nothing
        :rtype: str/none
        """
        # Perform check if all info to work with a user is given.
        # If not then immediately fail module run.
        # Done so a user email does not have to be provided if state == 'absent'.
        if before is None and email is None:
            return self.module.fail_json(
                msg="error: Email for creating user %s is missing " % username
            )
        if before is not None:
            built_email = dict(email=before["email"])
        if email is not None:
            built_email = dict(email=email)
        return built_email

    def build_name(self, before, username):
        """Creates a default name if none are provided as ns1-python lib appears to require one.

        :return: A name
        :rtype: str
        """
        if before is None and self.module.params["name"] is None:
            built_name = dict(name=username)
        if before is not None:
            built_name = dict(name=before["name"])
        if self.module.params["name"] is not None:
            built_name = dict(name=self.module.params["name"])
        return built_name

    def build_permissions(self, before):
        """Builds a complete set of permissions based on defaults with values
        updated by task parameters.

        :return: A complete set of permissions.
        :rtype: dict
        """
        default_permissions = dict(permissions=_default_perms)
        built_permissions = copy.deepcopy(default_permissions)
        if before is not None:
            before_copy = copy.deepcopy(before)
            built_permissions["permissions"] = before_copy["permissions"]
        for key in default_permissions["permissions"]:
            if "permissions" in self.module.params:
                if isinstance(self.module.params["permissions"], dict):
                    if key in self.module.params["permissions"]:
                        if isinstance(self.module.params["permissions"][key], dict):
                            for key_2, value_2 in self.module.params["permissions"][
                                key
                            ].items():
                                built_permissions["permissions"][key][key_2] = value_2
        return built_permissions

    def build_ip_whitelist(self):
        """Builds a list of dicts modeled to be the same as the API call.

        :return: A list of dicts
        :rtype: list
        """
        built_ip_whitelist = dict(ip_whitelist=[])
        if self.module.params["ip_whitelist"] is not None:
            built_ip_whitelist["ip_whitelist"] = self.module.params["ip_whitelist"]
        return built_ip_whitelist

    def build_teams(self):
        """Builds a list of strings modeled to be the same as the API call.

        :return: A list
        :rtype: list
        """
        built_teams = dict(teams=[])
        if self.module.params["teams"] is not None:
            team_list = self.ns1.team()
            for team in self.module.params["teams"]:
                for entry in team_list.list():
                    if entry["name"] == team:
                        built_teams["teams"].append(entry["id"])
        return built_teams

    def clean_data(self, data):
        """Removes output from API that we don't care about for accurate
        detection of changes.

        :param data: State of pre or post change.
        :type before: dict
        :return: Cleaned state data.
        :rtype: dict
        """
        if data is not None:
            keys = ["created","shared_auth", "last_access"]
            for key in keys:
                if key in data:
                    data.pop(key)
        return data

    def check_for_teams(self, before):
        """Does a check to see if team parameters are being provided and if
        so then remove permissions. The reason is due to user API updates with a
        team provided returns an empty permissions dict.

        :param before: Existing state of user.
        :type before: dict
        :return: User info before changes with permissions based on API behavior.
        :rtype: dict
        """
        if self.module.params["teams"] is not None:
            before["permissions"] = {}
        return before

    def build_changes(self, before, email, username):
        """Builds a complete API call by assembling returned data from functions.

        :return: A complete API call.
        :rtype: dict
        """
        # Create base dict of required module args for user creation/update.
        built_changes = dict(
            username=username,
        )
        built_changes.update({"2fa_enabled": self.module.params["two_fa_enabled"]})
        # Put into its own function for future proofing against possible future data structure growth.
        built_changes.update(self.build_notify())
        built_changes.update(self.build_email(before, email, username))
        built_changes.update(self.build_name(before, username))
        built_changes.update(
            {"ip_whitelist_strict": self.module.params["ip_whitelist_strict"]}
        )
        built_changes.update(self.build_ip_whitelist())
        built_changes.update(self.build_teams())
        built_changes.update(self.build_permissions(before))
        return built_changes

    def present(self, before, username):
        """Goes through the process of creating a new user, if needed, or
        updating a pre-existing one with new permissions.

        :param before: Existing user info if it exists.
        :type before: dict/none
        :param user_id: Previously collected id if the user exists.
        :type user_id: str
        :return: Tuple in which first value reflects whether or not a change
        occurred and second value is new or updated user object.
        :rtype: tuple(bool, dict)
        """
        changed = False
        after = None
        email = self.module.params.get("email")
        built_changes = self.build_changes(before, email, username)
        if self.module.check_mode:
            after = built_changes
        else:
            if before is None:
                after = self.create(built_changes)
            else:
                after = self.update(built_changes)
                before = self.check_for_teams(before)
        after = self.clean_data(after)
        before = self.clean_data(before)
        if after != before:
            changed = True
        return changed, after

    def absent(self, before, username):
        """Deletes an existing user or reports back no change if the user
        does not exist to start with.

        :param user_id: Previously collected id if the user exists.
        :type user_id: str
        :return: Tuple in which first value reflects whether or not a change
        occurred and second value is the removed user object.
        :rtype: tuple(bool, dict)
        """
        if before is None:
            return False
        else:
            self.delete(username)
            return True

    def check_existence(self, username):
        """Does a call to see if the user given in ansible task params already
        exists to establish existing state before changes are made. Also, this
        is the first step in getting user_id for later changes.

        :param username: Name parameter passed into the module from a task.
        :type username: str
        :return: user info before changes. If no info found then None will be returned.
        :rtype: dict/none
        """
        user_list = self.ns1.user()
        for user in user_list.list():
            if user["username"] == username:
                user_found = user
                return user_found

    def exec_module(self):
        """Main execution method of module.  Creates, updates or deletes a
        user based on Ansible parameters.

        :return: Results of module execution.
        :rtype: dict
        """
        # Setup and gather info
        # Retreive the name passed into the module from a task.
        username = self.module.params.get("username")
        # Creates a var that will contain data of an existing user or be a None Type.
        # The None type is used for determining state.
        before = self.check_existence(username)
        # Take action based on module params with gathered info passed in.
        # Retreive desired state passed into the module from a task.
        state = self.module.params.get("state")
        # Action based on a user state being set to present.
        # Will result in a user being created or updated.
        if state == "present":
            changed, after = self.present(before, username)
        # Action based on a user state being set to absent.
        # Assumes a user to remove already exists.
        if state == "absent":
            changed = self.absent(before, username)
            after = {}
        # Takes passed in state changes for id scrubbing and building of final output.
        return self.build_result(changed, after, before, username)

    def build_result(self, changed, after, before, username):
        """Builds dict of results from module execution to pass to module.exit_json()

        :param changed: Whether or not a change occurred.
        :type changed: bool
        :param user:
        :type user: dict
        :param before: Existing user info if it exists.
        :type before: dict/none
        :param username: Name parameter passed into the module from a task.
        :type username: str
        :return: Results of module execution.
        :rtype: dict
        """
        result = {"changed": changed}
        if self.module._diff:
            result.update(diff={"before": {}, "after": {}, "user": username})
            if before is not None:
                result["diff"]["before"] = before
            if after is not None:
                result["diff"]["after"] = after
        return result


def main():
    u = NS1user()
    result = u.exec_module()
    u.module.exit_json(**result)


if __name__ == "__main__":
    main()
