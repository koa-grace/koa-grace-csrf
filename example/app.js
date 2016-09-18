var koa = require('koa');
var csrf = require('..');

var app = koa();

app.use(csrf(app, {}));

app.use(function*() {
  this.body = '测试测试测试';
});

app.listen(3001, function() {
  console.log('Listening on 3001!');
});
