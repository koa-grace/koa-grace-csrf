'use strict';

const Tokens = require('./lib/csrf');
const debug = require('debug')('koa-grace:csrf');
const error = require('debug')('koa-grace-error:csrf');


module.exports = function Csrf(app, opts) {
  let tokens = new Tokens({
    saltLength: 8,
    secretLength: 18
  })

  let options = Object.assign({
    env: 'production',
    excluded: ['GET', 'HEAD', 'OPTIONS'],
    cookie_token: 'grace_token',
    cookie_key: 'grace_token_key',
    timeout: 30 * 86400 * 1000
  }, opts);

  return function* csrf(next) {

    if (options.excluded.indexOf(this.method) == -1) {
      let curSecret = this.cookies.get(options.cookie_key);
      // headers的key要转成小写
      let headerKey = options.cookie_token.toLowerCase();
      let curToken = (this.headers && this.headers[headerKey]) ||
        (this.query && this.query[options.cookie_token]) ||
        (this.request.body && this.request.body[options.cookie_token]);
      
      // token不存在
      if (!curToken || !curSecret) {
        error('CSRF Token Not Found: ' + this.req.url)
        // 暂时先不直接抛出错误
        // return this.throw('CSRF Token Not Found!',403)
      }

      // token校验失败
      if (!tokens.verify(curSecret, curToken)) {
        error('CSRF token Invalid: ' + this.req.url)
        // 暂时先不直接抛出错误
        // return this.throw('CSRF token Invalid!',403)
      }
    }

    yield next;

    // 无论何种情况都种两个cookie
    // cookie_key: 当前token的cookie_key,httpOnly
    let secret = tokens.secretSync();
    this.cookies.set(options.cookie_key, secret, {
      maxAge: options.timeout,
      httpOnly: true
    });
    // cookie_token: 当前token的的content，不需要httpOnly
    let newToken = tokens.create(secret);
    this.cookies.set(options.cookie_token, newToken, {
      maxAge: options.timeout,
      httpOnly: false
    })
  }
}
