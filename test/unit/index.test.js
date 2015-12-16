import chai, { assert } from 'chai';
import sinon from 'sinon';
import WeiboTokenStrategy from '../../src/index';
import fakeProfile from '../fixtures/profile.json';

const STRATEGY_CONFIG = {
  clientID: '123',
  clientSecret: '123'
};

const BLANK_FUNCTION = () => {
};

describe('WeiboTokenStrategy:init', () => {
  it('Should properly export Strategy constructor', () => {
    assert.isFunction(WeiboTokenStrategy);
  });

  it('Should properly initialize', () => {
    let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    assert.equal(strategy.name, 'weibo-token');
    assert.equal(strategy._oauth2._useAuthorizationHeaderForGET, false);
  });

  it('Should properly throw exception when options is empty', () => {
    assert.throw(() => new WeiboTokenStrategy(), Error);
  });
});

describe('WeiboTokenStrategy:authenticate', () => {
  describe('Authenticate without passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, JSON.stringify(fakeProfile), null));
    });

    after(() => strategy._oauth2.get.restore());

    it('Should properly parse access_token from body', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly parse access_token from query', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.query = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', done => {
      chai.passport.use(strategy).fail(error => {
        assert.typeOf(error, 'object');
        assert.typeOf(error.message, 'string');
        assert.equal(error.message, 'You should provide access_token');
        done();
      }).authenticate({});
    });
  });

  describe('Authenticate with passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new WeiboTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, (req, accessToken, refreshToken, profile, next) => {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, JSON.stringify(fakeProfile), null));
    });

    after(() => strategy._oauth2.get.restore());

    it('Should properly call _verify with req', done => {
      chai
        .passport
        .use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });

  describe('Failed authentications', () => {
    it('Should properly return error on loadUserProfile', done => {
      let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy, '_loadUserProfile', (accessToken, next) => next(new Error('Some error occurred')));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._loadUserProfile.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', done => {
      let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(new Error('Some error occurred'));
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, JSON.stringify(fakeProfile), null));

      chai
        .passport
        .use(strategy)
        .error(error => {
          assert.instanceOf(error, Error);
          strategy._oauth2.get.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly return error on verified', done => {
      let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, null, 'INFO');
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, JSON.stringify(fakeProfile), null));

      chai
        .passport
        .use(strategy)
        .fail(error => {
          assert.equal(error, 'INFO');
          strategy._oauth2.get.restore();
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('WeiboTokenStrategy:userProfile', () => {
  it('Should properly fetch profile', done => {
    let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);
    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, JSON.stringify(fakeProfile), null));

    strategy.userProfile('accessToken', (error, profile) => {
      if (error) return done(error);

      assert.equal(profile.provider, 'weibo');
      assert.equal(profile.id, '​1947261240');
      assert.equal(profile._json.id, '​​1947261240');
      assert.equal(profile.displayName, 'KaLun1988');
      assert.equal(profile.gender, 'male');
      // assert.equal(profile.emails[0].value, 'ghaiklor@gmail.com');
      assert.equal(profile.photos[0].value, 'http://tp1.sinaimg.cn/1947261240/50/5732080843/1');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      strategy._oauth2.get.restore();

      done();
    });
  });

  it('Should properly handle exception on fetching profile', done => {
    let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, 'not a JSON'));

    strategy.userProfile('accessToken', (error, profile) => {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      strategy._oauth2.get.restore();
      done();
    });
  });

  it('Should properly throw error on _oauth2.get error', done => {
    let strategy = new WeiboTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next('Some error occurred'));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.instanceOf(error, Error);
      strategy._oauth2.get.restore();
      done();
    });
  });
});

describe('WeiboTokenStrategy:convertProfileFields', () => {
  it('Should properly return string with pre-defined fields', () => {
    let string = WeiboTokenStrategy.convertProfileFields();
    assert.equal(string, '');
  });

  it('Should properly return string with custom fields', () => {
    let string = WeiboTokenStrategy.convertProfileFields(['username', 'name', 'emails', 'custom']);
    assert.equal(string, 'username,last_name,first_name,middle_name,email,custom');
  });
});
