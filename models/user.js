var mongoose = require("mongoose");
var bcrypt = require("bcrypt");

var User = new mongoose.Schema({
  name: {type: String},
  email: {type: String, required: true, unique: true},
  password: {type: String, required: true}
});

User.pre('save', function(next){
  var user = this;
  if(!user.isModified('password')) return next();
  bcrypt.genSalt(5, function(err,salt){
    if(err) return next(err); 
    bcrypt.hash(user.password, salt, function(err,hash){
      if(err) return next(err); 
      user.password = hash;
      next();
    })
  })
})

User.methods.authenticate = function(password, callback){
  bcrypt.compare(password, this.password, function(err, isMatch){
    callback(null, isMatch);
  })
}

module.exports = mongoose.model("User", User);
