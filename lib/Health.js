


var Health = function(req, res, next) {


	if (req.path === '/' && req.headers["user-agent"] && req.headers["user-agent"].match(/GoogleHC/)) {
		return res.json({"status": "ok"});
	}

	// console.log("Req path " + req.path);
	// console.log("HEaders", req.headers["user-agent"]);
	return next();
};


exports.Health = Health;