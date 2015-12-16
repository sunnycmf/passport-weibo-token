import uri from 'url';
import crypto from 'crypto';
import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

/**
 * `WeiboTokenStrategy` constructor.
 *
 * The Sina Weibo authentication strategy authenticates requests by delegating to
 * Sina Weibo using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * @param {Object} options
 * @param {Function} verify
 * @example
 * passport.use(new WeiboTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), (accessToken, refreshToken, profile, done) => {
 *   User.findOrCreate({weiboId: profile.id}, done);
 * });
 */
export default class WeiboTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://api.weibo.com/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://api.weibo.com/oauth2/access_token';

    super(options, verify);

    this.name = 'weibo-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._getUidURL = options._getUidURL || 'https://api.weibo.com/2/account/get_uid.json';
    this._profileURL = options.profileURL || 'https://api.weibo.com/2/users/show.json';
    this._profileFields = options.profileFields || ['id', 'name', 'emails'];
    this._clientSecret = options.clientSecret;
    this._enableProof = typeof options.enableProof === 'boolean' ? options.enableProof : true;
    this._passReqToCallback = options.passReqToCallback;

    // this._oauth2.useAuthorizationHeaderforGET(false);
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   * @param {Object} req
   * @param {Object} options
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Retrieve user profile from Weibo.
   *
   * This function constructs a normalized profile, with the following properties:
   *
   *   - `provider`         always set to `weibo`
   *   - `id`               the user's Sina Weibo ID
   *   - `username`         the user's Sina Weibo username
   *   - `displayName`      the user's full name
   *   - `gender`           the user's gender: `male` or `female`
   *   - `profileUrl`       the URL of the profile for the user on Weibo
   *
   * @param {String} accessToken
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    this._oauth2.get(this._getUidURL, accessToken, (error, body, res) => {
      if (error) return done(new InternalOAuthError('Failed to fetch uid', error));
      let uid;

      try {
        uid = JSON.parse(body).uid;
      }catch (e){
        done(e);
      }
      
      this._oauth2.get(this._profileURL + '?uid=' + uid , accessToken, (error, body, res) => {
        if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

        try {
          let json = JSON.parse(body);
          let profile = {
            provider: 'weibo',
            id: json.id,
            displayName: json.name || '',
            name: {
              familyName: json.last_name || '',
              givenName: json.first_name || '',
              middleName: json.middle_name || ''
            },
            gender: json.gender || '',
            emails: [{
              value: json.email || ''
            }],
            photos: [{
              value: json.profile_image_url
            }],
            _raw: body,
            _json: json
          };

          done(null, profile);
        } catch (e) {
          done(e);
        }
      });
    });
  }

  /**
   * Converts array of profile fields to string
   * @param {Array} _profileFields Profile fields i.e. ['id', 'email']
   * @returns {String}
   */
  static convertProfileFields(_profileFields) {
    let profileFields = _profileFields || [];
    let map = {
      'id': 'id',
      'displayName': 'screen_name',
      'gender': 'gender',
      'profileUrl': 'profile_url',
      'photos': 'profile_image_url'
    };

    return profileFields.reduce((acc, field) => acc.concat(map[field] || field), []).join(',');
  }
}
