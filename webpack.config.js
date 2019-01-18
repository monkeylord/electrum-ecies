module.exports = {
	entry: __dirname + "/index.js",
    externals: {
        bsv: 'bsv'
    },
	output: {
        library: "ecies",
		path: __dirname + "/",
		filename: "ecies.js"
	}
}