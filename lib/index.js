'use strict';

Object.defineProperty(exports, '__esModule', {
  value: true
});

var _createClass = (function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ('value' in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; })();

var _get = function get(_x, _x2, _x3) { var _again = true; _function: while (_again) { var object = _x, property = _x2, receiver = _x3; _again = false; if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { _x = parent; _x2 = property; _x3 = receiver; _again = true; desc = parent = undefined; continue _function; } } else if ('value' in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } } };

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError('Cannot call a class as a function'); } }

function _inherits(subClass, superClass) { if (typeof superClass !== 'function' && superClass !== null) { throw new TypeError('Super expression must either be null or a function, not ' + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var _url = require('url');

var _url2 = _interopRequireDefault(_url);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _passportOauth = require('passport-oauth');

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

var WeiboTokenStrategy = (function (_OAuth2Strategy) {
  _inherits(WeiboTokenStrategy, _OAuth2Strategy);

  function WeiboTokenStrategy(_options, _verify) {
    _classCallCheck(this, WeiboTokenStrategy);

    var options = _options || {};
    var verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://api.weibo.com/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://api.weibo.com/oauth2/access_token';

    _get(Object.getPrototypeOf(WeiboTokenStrategy.prototype), 'constructor', this).call(this, options, verify);

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

  _createClass(WeiboTokenStrategy, [{
    key: 'authenticate',
    value: function authenticate(req, options) {
      var _this = this;

      var accessToken = req.body && req.body[this._accessTokenField] || req.query && req.query[this._accessTokenField];
      var refreshToken = req.body && req.body[this._refreshTokenField] || req.query && req.query[this._refreshTokenField];

      if (!accessToken) return this.fail({ message: 'You should provide ' + this._accessTokenField });

      this._loadUserProfile(accessToken, function (error, profile) {
        if (error) return _this.error(error);

        var verified = function verified(error, user, info) {
          if (error) return _this.error(error);
          if (!user) return _this.fail(info);

          return _this.success(user, info);
        };

        if (_this._passReqToCallback) {
          _this._verify(req, accessToken, refreshToken, profile, verified);
        } else {
          _this._verify(accessToken, refreshToken, profile, verified);
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
  }, {
    key: 'userProfile',
    value: function userProfile(accessToken, done) {
      var _this2 = this;

      this._oauth2.get(this._getUidURL, accessToken, function (error, body, res) {
        if (error) return done(new _passportOauth.InternalOAuthError('Failed to fetch uid', error));
        var uid = undefined;

        try {
          uid = JSON.parse(body).uid;
        } catch (e) {
          done(e);
        }

        _this2._oauth2.get(_this2._profileURL + '?uid=' + uid, accessToken, function (error, body, res) {
          if (error) return done(new _passportOauth.InternalOAuthError('Failed to fetch user profile', error));

          try {
            var json = JSON.parse(body);
            var profile = {
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
  }], [{
    key: 'convertProfileFields',
    value: function convertProfileFields(_profileFields) {
      var profileFields = _profileFields || [];
      var map = {
        'id': 'id',
        'displayName': 'screen_name',
        'gender': 'gender',
        'profileUrl': 'profile_url',
        'photos': 'profile_image_url'
      };

      return profileFields.reduce(function (acc, field) {
        return acc.concat(map[field] || field);
      }, []).join(',');
    }
  }]);

  return WeiboTokenStrategy;
})(_passportOauth.OAuth2Strategy);

exports['default'] = WeiboTokenStrategy;
module.exports = exports['default'];