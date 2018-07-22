// Interceptor for 'malloc'
Interceptor.attach(Module.findExportByName(null, 'malloc'),
		{
			// Log before malloc
			onEnter: function (args) {
				console.log("malloc(" + args[0].toInt32() + ")");
			},
			// Log after malloc
			onLeave: function (retval) {
				console.log("\t\t= 0x" + retval.toString(16));
			}
		});

// Interceptor for 'free'
Interceptor.attach(Module.findExportByName(null, 'free'),
		{
			onEnter: function (args) {
				console.log("free(0x" + args[0].toString(16) + ")");
			}
		});