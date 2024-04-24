EXPLAINATIONS = {
	'1000002': 'A device in your network is trying different passwords to illegally access another machine through SSH, which is a common method for securely connecting to another computer.',
	'1000003': 'A device in your network is sending harmful data to another machine\'s database through a website or app, trying to trick it into giving out unauthorized information or access.',
	'1000004': 'A device in your network is sending "ping" messages to another machine to see if it is online and how quickly it responds, similar to saying "hello" to check if someone is home.',
	'1000005': 'A device in your network is using the Tor network, which helps users browse the internet anonymously, hiding their activities and location.',
}

REMEDIATIONS = {
	'1000002': 'If you know this device, strengthen its security by using strong, complex passwords, enabling two-factor authentication, and limiting SSH access to known IP addresses.',
	'1000003': 'If you know which webapp this is, protect it by ensuring your website code properly checks and sanitizes all user inputs, and use prepared statements and parameterized queries in your database interactions.',
	'1000004': 'Configure your firewall to block or restrict ICMP ping requests to essential services only, minimizing the information an attacker can gather about your network.',
	'1000005': 'Monitor network traffic and block Tor entry and exit nodes if necessary, especially if Tor usage violates your network\'s usage policies or security requirements.',
}