/* global describe, it, expect, before */
/* jshint expr: true */

var GitHubStrategy = require('../lib');
var SinaAPIError = require('../lib/error');
var data = require('./data/example.json');


describe('Strategy#userProfile', function() {

  var strategy =  new GitHubStrategy({
      clientID: 'ABC123',
      clientSecret: 'secret'
    },
    function() {});

  // mock
  strategy._oauth2.getProtectedResource = function(url, accessToken, callback) {
    if (accessToken != 'token') { return callback(new Error('wrong token argument')); }

    var body = JSON.stringify(data);
    callback(null, body, undefined);
  };

  describe('loading profile', function() {
    var profile;

    before(function(done) {
      strategy.userProfile('token', function(err, p) {
        if (err) { return done(err); }
        profile = p;
        done();
      });
    });

    it('should parse profile', function() {
      expect(profile.provider).to.equal('sina');

      expect(profile.id).to.equal(data.id);
      expect(profile.name).to.equal(data.name);
      expect(profile.screen_name).to.equal(data.screen_name);
      expect(profile.profile_url).to.equal(data.profile_url);
    });

    it('should set raw property', function() {
      expect(profile._raw).to.be.a('string');
    });

    it('should set json property', function() {
      expect(profile._json).to.be.an('object');
    });
  });

  describe('encountering an error', function() {
    var err, profile;

    before(function(done) {
      strategy.userProfile('wrong-token', function(e, p) {
        err = e;
        profile = p;
        done();
      });
    });

    it('should error', function() {
      expect(err).to.be.an.instanceOf(Error);
      expect(err).to.be.an.instanceOf(SinaAPIError);
    });

    it('should not load profile', function() {
      expect(profile).to.be.undefined;
    });
  });

});
