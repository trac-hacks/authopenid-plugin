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
		label : '輸入您AOL的螢幕名稱.',
		url : 'http://openid.aol.com/{username}'
	},
	myopenid : {
		name : 'MyOpenID',
		label : '輸入您MyOpenID的用戶名稱.',
		url : 'http://{username}.myopenid.com/'
	},
	openid : {
		name : 'OpenID',
		label : '輸入您的OpenID.',
		url : null
	}
};

var providers_small = {
	livejournal : {
		name : 'LiveJournal',
		label : '輸入您Livejournal的用戶名稱.',
		url : 'http://{username}.livejournal.com/'
	},
	/* flickr: {
		name: 'Flickr',        
		label: '輸入您Flickr的用戶名稱.',
		url: 'http://flickr.com/{username}/'
	}, */
	/* technorati: {
		name: 'Technorati',
		label: '的用戶名稱Technorati的用戶名稱.',
		url: 'http://technorati.com/people/technorati/{username}/'
	}, */
	wordpress : {
		name : 'Wordpress',
		label : '輸入您Wordpress.com username.',
		url : 'http://{username}.wordpress.com/'
	},
	blogger : {
		name : 'Blogger',
		label : '您的Blogger帳號',
		url : 'http://{username}.blogspot.com/'
	},
	verisign : {
		name : 'Verisign',
		label : '您Verisign的用戶名稱 ',
		url : 'http://{username}.pip.verisignlabs.com/'
	},
	/* vidoop: {
		name: 'Vidoop',
		label: '您Vidoop的用戶名稱',
		url: 'http://{username}.myvidoop.com/'
	}, */
	/* launchpad: {
		name: 'Launchpad',
		label: '您Launchpad的用戶名稱',
		url: 'https://launchpad.net/~{username}'
	}, */
	claimid : {
		name : 'ClaimID',
		label : '您ClaimID的用戶名稱',
		url : 'http://claimid.com/{username}'
	},
	clickpass : {
		name : 'ClickPass',
		label : '輸入您ClickPass的用戶名稱',
		url : 'http://clickpass.com/public/{username}'
	},
	google_profile : {
		name : 'Google Profile',
		label : '輸入您Google個人資料的用戶名稱',
		url : 'http://www.google.com/profiles/{username}'
	}
};

openid.locale = 'zh_TW';
openid.sprite = 'en'; // reused in german& japan localization
openid.demo_text = '客戶端展示模式,通常提交的OpenID是:';
openid.signin_text = '登入';
openid.image_title = '以{provider}登入';
