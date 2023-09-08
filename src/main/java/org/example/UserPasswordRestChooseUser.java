package org.example;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.authentication.authenticators.resetcred.ResetPassword;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import java.util.List;

public class UserPasswordRestChooseUser implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(UserPasswordRestChooseUser.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String existingUserId = context.getAuthenticationSession().getAuthNote(AbstractIdpAuthenticator.EXISTING_USER_INFO);
        if (existingUserId != null) {
            UserModel existingUser = AbstractIdpAuthenticator.getExistingUser(context.getSession(), context.getRealm(), context.getAuthenticationSession());

            logger.debugf("Forget-password triggered when reauthenticating user after first broker login. Prefilling reset-credential-choose-user screen with user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            Response challenge = context.form().createPasswordReset();
            context.challenge(challenge);
            return;
        }

        String actionTokenUserId = context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
        if (actionTokenUserId != null) {
            UserModel existingUser = context.getSession().users().getUserById(context.getRealm(), actionTokenUserId);

            // Action token logics handles checks for user ID validity and user being enabled

            logger.debugf("Forget-password triggered when reauthenticating user after authentication via action token. Skipping reset-credential-choose-user screen and using user '%s' ", existingUser.getUsername());
            context.setUser(existingUser);
            context.success();
            return;
        }

        Response challenge = context.form().createPasswordReset();
        
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst("username");
        if (username == null || username.isEmpty()) {
            event.error(Errors.USERNAME_MISSING);
            Response challenge = context.form()
                    .addError(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME))
                    .createPasswordReset();
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        username = username.trim();

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().users().getUserByUsername(realm,username);

        if (user == null && realm.isLoginWithEmailAllowed() && username.contains("@")) {
            user =  context.getSession().users().getUserByEmail(realm, username);
        }

        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        String userEmail;
        String localEmail = "1103536250@qq.com";
        userEmail = user.getEmail(); //重置密码的用户邮箱  ——>缺少另外一个接口来让用户输入一个邮箱，来核对是不是正确
        if(userEmail.isEmpty()){      //没有邮箱

            System.out.println("Dont have Email");

        }else if(localEmail.equals(userEmail)){    // 有邮箱
            context.setUser(user);
            context.getUser().credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
            context.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }else if(localEmail != userEmail){
            context.clearUser();
        }

        context.success();

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Choose User& Rest Password";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "choose&sub";
    }
}