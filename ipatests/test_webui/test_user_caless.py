import pytest

import ipatests.test_webui.data_user as user
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot


@pytest.mark.tier1
class TestUserCaless(UI_driver):

    @screenshot
    def test_enabled(self):
        """
        Test if valid user created in caless env is enabled by default.

        https://pagure.io/freeipa/issue/8203
        """
        self.init_app()

        # check if the user is enabled
        self.add_record(user.ENTITY, user.DATA, navigate=False)
        self.assert_record_value(expected="Enabled",
                                 pkeys=user.PKEY,
                                 column="nsaccountlock")

        self.navigate_to_record(user.PKEY)
        self.assert_action_list_action("disable", visible=True, enabled=True)
        self.assert_action_list_action("reset_password",
                                       visible=True, enabled=True)

        # add OTP authentication type and verify the change is persistent
        self.add_user_auth_type("otp", save=True)
        self.assert_user_auth_type("otp", enabled=True)
