# cfwlogd

The userland daemon responsible for reading cloud firewall events from an ipf
kernel device and translating them into json log messages and writing them out
to log files.

## Program structure

cfwlogd:
  - vminfod thread managing `HashMap<zonedid, vmobj>`
  - ipf consumer thread(s)
  - log file writing threads (separate from ipf consumer?)

## Things to consider

- Mio support for event ports

	I think this is a definite want but with the relatively low activity
	of a vminfod event stream I don't think its a blocker for the initial
	program

- Use crossbeam::sync::SharedLock

	Faster reads with slower writes. I expect writes to be infrequent. A
	write should only really happen when we see a VM undergo one of the
	following operations:
	* Startup via the `Ready` event from vminfod
	* Create
	* Destroy
	* Update (but only the alias)
