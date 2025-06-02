import { RemovalPolicy } from 'aws-cdk-lib';
import {
  AccountRecovery,
  CfnUserPoolGroup,
  ManagedLoginVersion,
  OAuthScope,
  OidcAttributeRequestMethod,
  ProviderAttribute,
  UserPool,
  UserPoolClient,
  UserPoolIdentityProviderOidc,
  UserPoolOperation,
} from 'aws-cdk-lib/aws-cognito';
import { Key } from 'aws-cdk-lib/aws-kms';
import { IFunction } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { AuthNestedStackProps } from '../types/back-end-stack';

export interface CognitoIDPConstructProps extends AuthNestedStackProps {
  authLambdaFunctions?: Map<string, IFunction>;
  customSenderKmsKey?: Key;
}

export class CognitoIdpConstruct extends Construct {
  readonly props: CognitoIDPConstructProps;
  readonly userPool: UserPool;
  readonly userPoolClient: UserPoolClient;
  readonly userPoolIdentityProviderOidc: UserPoolIdentityProviderOidc;
  readonly userPoolGroup: CfnUserPoolGroup;

  constructor(scope: Construct, id: string, props: CognitoIDPConstructProps) {
    super(scope, id);
    this.props = props;
    const removalPolicy = props.envType !== 'prod' ? RemovalPolicy.DESTROY : undefined; // Only for Non-Prod

    // The auth construct defines Cognito Resources for user authentication.
    this.userPool = new UserPool(this, 'user-pool', {
      userPoolName: `${props.constructNamespace}-user-pool`,
      selfSignUpEnabled: false,
      accountRecovery: AccountRecovery.EMAIL_ONLY,
      signInCaseSensitive: false,
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
        phone: false,
      },
      passwordPolicy: {
        minLength: 8,
        requireDigits: true,
        requireLowercase: true,
        requireUppercase: true,
        requireSymbols: true,
      },
      customSenderKmsKey: props.customSenderKmsKey,
      removalPolicy: removalPolicy,
    });

    this.userPool.addDomain('domain', {
      cognitoDomain: {
        domainPrefix: `${this.props.constructNamespace}`,
      },
      managedLoginVersion: ManagedLoginVersion.CLASSIC_HOSTED_UI,
    });

    if (true) {
      this.userPoolIdentityProviderOidc = new UserPoolIdentityProviderOidc(this, 'federated-oidc', {
        name: 'easy-genomics-federated-oidc', // Config | UI setting per Org
        clientId: '3gnhf2s89dvs50drau5rlooe8e', // Config | UI setting per Org
        clientSecret: '12rvgnijhckehstva1g7hnhapbn3mbdje61rpuottobcf9tdvfi2', // Config | UI setting per Org
        issuerUrl: 'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_i9LvH2hm1', // Config | UI setting per Org
        userPool: this.userPool,
        attributeMapping: {
          email: ProviderAttribute.other('email'),
          givenName: ProviderAttribute.other('given_name'),
          familyName: ProviderAttribute.other('family_name'),
        },
        attributeRequestMethod: OidcAttributeRequestMethod.POST,
      });
    }

    this.userPoolClient = this.userPool.addClient('client', {
      userPoolClientName: `${props.constructNamespace}-user-pool-client`,
      generateSecret: true,
      preventUserExistenceErrors: true,
      authFlows: {
        userSrp: true,
      },
      oAuth: {
        scopes: [OAuthScope.EMAIL, OAuthScope.OPENID, OAuthScope.PROFILE],
      },
    });

    this.userPoolGroup = new CfnUserPoolGroup(this, 'system-admin-user-pool-group', {
      userPoolId: this.userPool.userPoolId,
      // the properties below are optional
      description: 'SystemAdmin Group',
      groupName: 'SystemAdmin',
      precedence: 0,
    });

    if (props.authLambdaFunctions) {
      /** AWS Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html **/
      // Authentication Events
      this.addCognitoLambdaTrigger(
        UserPoolOperation.PRE_AUTHENTICATION,
        props.authLambdaFunctions.get('/auth/process-pre-authentication'),
      );
      this.addCognitoLambdaTrigger(
        UserPoolOperation.POST_AUTHENTICATION,
        props.authLambdaFunctions.get('/auth/process-post-authentication'),
      );
      this.addCognitoLambdaTrigger(
        UserPoolOperation.PRE_TOKEN_GENERATION,
        props.authLambdaFunctions.get('/auth/process-pre-token-generation'),
      );
      // Sign-Up
      this.addCognitoLambdaTrigger(
        UserPoolOperation.PRE_SIGN_UP,
        props.authLambdaFunctions.get('/auth/process-pre-signup'),
      );
      this.addCognitoLambdaTrigger(
        UserPoolOperation.POST_CONFIRMATION,
        props.authLambdaFunctions.get('/auth/process-post-confirmation'),
      );
      this.addCognitoLambdaTrigger(
        UserPoolOperation.USER_MIGRATION,
        props.authLambdaFunctions.get('/auth/process-user-migration'),
      );
      // Messages
      this.addCognitoLambdaTrigger(
        UserPoolOperation.CUSTOM_MESSAGE,
        props.authLambdaFunctions.get('/auth/process-custom-message'),
      );
      // Email & SMS 3rd party providers
      this.addCognitoLambdaTrigger(
        UserPoolOperation.CUSTOM_EMAIL_SENDER,
        props.authLambdaFunctions.get('/auth/process-custom-email-sender'),
      );
      this.addCognitoLambdaTrigger(
        UserPoolOperation.CUSTOM_SMS_SENDER,
        props.authLambdaFunctions.get('/auth/process-custom-sms-sender'),
      );
    }
  }

  /**
   * Helper function to register a Lambda function for Cognito Trigger Event.
   *
   * If the auth lambdaFunction is undefined, then the associated Cognito Trigger Event will not have a registered function.
   *
   * @param userPoolOperation
   * @param lambdaFunction
   * @private
   */
  private addCognitoLambdaTrigger(userPoolOperation: UserPoolOperation, lambdaFunction?: IFunction) {
    if (lambdaFunction) {
      this.userPool.addTrigger(userPoolOperation, lambdaFunction);

      // Grant Lambda function permission to Decrypt
      if (this.props.customSenderKmsKey) {
        this.props.customSenderKmsKey.grantDecrypt(lambdaFunction);
      }
    }
  }
}
