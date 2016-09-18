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
    secret: tokens.secretSync(),
    cookie: 'GRACE_TOKEN'
  }, opts);

  return function* csrf(next) {

    if (options.excluded.indexOf(this.method) == -1) {
      let graceToken = (this.query && this.query[options.cookie]) ||
        (this.request.body && this.request.body[options.cookie]);
      
      // token不存在
      if (!graceToken) {
        error('CSRF Token Not Found: ' + this.req.url)
        // 暂时先不直接抛出错误
        // return this.throw('CSRF Token Not Found!',403)
      }

      // token校验失败
      if (!tokens.verify(options.secret, graceToken)) {
        error('CSRF token Invalid: ' + this.req.url)
        // 暂时先不直接抛出错误
        // return this.throw('CSRF token Invalid!',403)
      }
    }

    yield next;

    // 无论何种情况都种一个cookie，保证最新状态
    let newToken = tokens.create(options.secret);

    this.cookies.set(options.cookie, newToken, {
      maxAge: 30 * 86400 * 1000
    })
  }
}
