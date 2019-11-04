import logging
from datetime import timedelta, datetime as dt
from enum import Enum, unique
from random import choices
from re import findall
from string import ascii_lowercase
from textwrap import dedent

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

logger = logging.getLogger(__name__)


class TestDisableStaleUser(IntegrationTest):
    """
    Test class for testing Disable Stale Users (DSU) functionality
    """
    topology = 'line'

    @unique
    class ExpirationTime(Enum):
        future = 100
        soon = 2
        grace = -5
        expired = -100

    et = ExpirationTime  # alias for shorter name

    @staticmethod
    def _generate_user(*, login: str, first_name: str = None,
                       last_name: str = None,
                       expiration_status: ExpirationTime) -> list:
        """ Generates user information with provided arguments

        :param login: login name of the user
        :param first_name: first name of the user, random if not provided
        :param last_name: last name of the user, random if not provided
        :param expiration_status: future, soon, grace or expired,
        this parameter is used to calculate expiration date for user's password
        :return: expandable list with user information in format required
        by ipa user-add directive
        """
        return [login,
                "--first",
                first_name if first_name else ''.join(
                    choices(ascii_lowercase, k=5)),
                "--last",
                last_name if last_name else ''.join(
                    choices(ascii_lowercase, k=5)),
                "--random",
                "--password-expiration",
                dt.strftime(dt.now() + timedelta(days=expiration_status.value),
                            "%Y%m%d%H%M%SZ")]

    @classmethod
    def _generate_users_list(cls, login_pattern: str, number_of_users: int,
                             expiration_status: ExpirationTime) -> list:
        return [cls._generate_user(login=login_pattern.format(i),
                                   expiration_status=expiration_status)
                for i in range(number_of_users)]

    @classmethod
    def _set_krb_last_auth_attr(cls, *, uid: str,
                                expiration_status: ExpirationTime) -> None:
        """Set krbLastSuccessfulAuth parameter in LDAP to comply with desired
        expiration status

        :param uid: uid of the user to be edited
        :param expiration_status: future, soon, grace or expired,
        this parameter is used to calculate krbLastSuccessfulAuth attribute
        :return: None, modification is done in LDAP database
        """
        modification_ldif = dedent("""
            dn: uid={user},cn=users,cn=accounts,{base_dn}
            changetype: modify
            replace: krbLastSuccessfulAuth
            krbLastSuccessfulAuth: {new_time}""".format(
            user=uid,
            base_dn=cls.master.base_dn,  # pylint: disable=no-member
            new_time=dt.strftime(dt.now() + timedelta(
                days=expiration_status.value), "%Y%m%d%H%M%SZ")
        ))
        tasks.ldapmodify_dm(cls.master, modification_ldif)

    @classmethod
    def _configure_users(cls) -> None:
        """Set required users and register them to IPA

        :return: None
        """
        _users_per_list = 9
        # generate multiple users per expiration status
        not_expiring_users = cls._generate_users_list("ne_user_{}",
                                                      _users_per_list,
                                                      cls.et.future)
        expired_users_grace = cls._generate_users_list("eg_user_{}",
                                                       _users_per_list,
                                                       cls.et.grace)
        soon_expiring_users = cls._generate_users_list("se_user_{}",
                                                       _users_per_list,
                                                       cls.et.soon)
        expired_users_past = cls._generate_users_list("e_user_{}",
                                                      _users_per_list,
                                                      cls.et.
                                                      expired)
        soon_expiring_inactive_users = cls._generate_users_list(
            "sei_user_{}",
            _users_per_list,
            cls.et.soon)

        # register above generated users
        tasks.kinit_admin(cls.master)
        _generated_user_passwords = {}
        for user in zip(not_expiring_users, expired_users_grace,
                        soon_expiring_users, expired_users_past,
                        soon_expiring_inactive_users):
            res = cls.master.run_command(['ipa', 'user-add', *user])
            # obtain randomly generated password
            _psswd = findall('Random password: (.+)\n', res.stdout_text)[-1]
            _generated_user_passwords[user] = _psswd

        # kinit soon_expiring_inactive_users,
        # so their krbLastSuccessfulAuth parameter is created
        for user in soon_expiring_inactive_users:
            tasks.kinit_as_user(cls.master,
                                user,
                                _generated_user_passwords[user])
        tasks.kdestroy_all(cls.master)

        # change soon_expiring_inactive_users' krbLastSuccessfulAuth parameter
        tasks.kinit_admin(cls.master)
        for user in soon_expiring_inactive_users:
            cls._set_krb_last_auth_attr(
                uid=user,
                expiration_status=cls.et.expired)

    @classmethod
    def _change_ipa_dsu_config(cls) -> None:
        # TODO: fill-in ipa-dsu configuration file
        pass

    @classmethod
    def install(cls, mh):
        super(TestDisableStaleUser, cls).install(mh)

        # enable krbLastSuccessfulAuth parameter in LDAP
        cls.master.run_command(['ipa', 'config-mod',
                                '--delattr',
                                'ipaConfigString="KDC:Disable Last Success"'])

        # restart IPA to render above executed changes
        cls.master.run_command(['ipaclt', 'restart'])

        cls._configure_users()

    @classmethod
    def teardown_class(cls):
        # TODO: Remove non-removed users
        pass

    def test_dsu_dry_run(self):
        res = self.master.run_command(['ipa-dsu', '--dry-run'])
        del res  # temp
        assert True

    def test_dsu_full_run(self):
        res = self.master.run_command(['ipa-dsu'])
        del res  # temp
        assert True
