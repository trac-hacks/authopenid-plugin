/*
	Simple OpenID Plugin
	http://code.google.com/p/openid-selector/
	
	This code is licensed under the New BSD License.
*/

var providers_large = {
	google : {
		name : 'Google',
		url : 'https://www.google.com/accounts/o8/id'
	},
	yahoo : {
		name : 'Yahoo',
		url : 'http://me.yahoo.com/'
	},
	aol : {
		name : 'AOL',
		label : 'Entrez votre nom d\'utilisateur AOL.',
		url : 'http://openid.aol.com/{username}'
	},
	myopenid : {
		name : 'MyOpenID',
		label : 'Entrez votre nom d\'utilisateur MyOpenID.',
		url : 'http://{username}.myopenid.com/'
	},
	openid : {
		name : 'OpenID',
		label : 'Entrez votre OpenID.',
		url : null
	}
};

var providers_small = {
	livejournal : {
		name : 'LiveJournal',
		label : 'Entrez votre nom d\'utilisateur Livejournal.',
		url : 'http://{username}.livejournal.com/'
	},
	wordpress : {
		name : 'Wordpress',
		label : 'Entrez votre nom d\'utilisateur Wordpress.com.',
		url : 'http://{username}.wordpress.com/'
	},
	blogger : {
		name : 'Blogger',
		label : 'Entrez votre nom d\'utilisateur Blogger',
		url : 'http://{username}.blogspot.com/'
	},
	verisign : {
		name : 'Verisign',
		label : 'Entrez votre nom d\'utilisateur Verisign',
		url : 'http://{username}.pip.verisignlabs.com/'
	},
	claimid : {
		name : 'ClaimID',
		label : 'Entrez votre nom d\'utilisateur ClaimID',
		url : 'http://claimid.com/{username}'
	},
	clickpass : {
		name : 'ClickPass',
		label : 'Entrez votre nom d\'utilisateur ClickPass',
		url : 'http://clickpass.com/public/{username}'
	},
	google_profile : {
		name : 'Google Profile',
		label : 'Entrez votre nom d\'utilisateur Google Profile',
		url : 'http://www.google.com/profiles/{username}'
	}
};

openid.locale = 'fr';
openid.sprite = 'en'; // reused in german& japan localization
openid.demo_text = 'Mode de démonstration. Normalement, l\'OpenID suivant aurait été envoyé : ';
openid.signin_text = 'Se connecter';
openid.image_title = 'Se connecter grâce à {provider}';
