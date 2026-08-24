<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Word-based pairing for remote device authorization.
 *
 * Flow:
 *   1. Admin clicks "Start Word Pairing" → server generates 3 code words encoding a session
 *   2. Admin tells device owner the 3 words (phone call, text, etc.)
 *   3. Device owner enters words → daemon fetches pairing session from server
 *   4. Both sides perform ECDH (crypto_kx), derive SAS (3 verification words)
 *   5. Admin and device owner compare SAS words out-of-band
 *   6. If match, admin confirms → device's Ed25519 pk is decrypted and authorized
 *
 * The 3-word code has ~33 bits of entropy. The SAS verification provides
 * a second layer of authentication - both sides must see the same 3 words.
 * Always verify SAS words over a separate channel (phone call, video call, etc.).
 */
class WC_XMR_Push_Pairing {

	const OPTION        = 'wc_xmr_push_pairings';
	const TTL_SECONDS   = 300; // 5 minutes
	const MAX_ACTIVE    = 5;
	const NONCE_BYTES   = 5;  // 40 bits → 3 BIP39 words (33 bits used)

	/**
	 * BIP39 English wordlist (2048 words).
	 * Each word encodes 11 bits. 2 words = 22 bits = ~4 million codes.
	 */
	const WORDLIST = array(
		'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
		'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
		'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
		'adult','advance','advice','aerobic','affair','afford','afraid','africa','after','again',
		'age','agent','agree','ahead','aim','air','airport','aisle','alarm','album',
		'alcohol','alert','alien','all','alley','allow','almost','alone','alpha','already',
		'also','alter','always','amateur','amazing','among','amount','amused','analyst','anchor',
		'ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer',
		'antenna','antique','anxiety','any','apart','apology','appear','apple','approve','april',
		'arch','arctic','area','arena','argue','arm','armed','armor','army','around',
		'arrange','arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect',
		'assault','asset','assist','assume','asthma','athlete','atom','attack','attend','attitude',
		'attract','auction','audit','august','aunt','author','auto','autumn','average','avocado',
		'avoid','awake','aware','away','awesome','awful','awkward','axis','baby','bachelor',
		'bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar',
		'barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty',
		'because','become','beef','before','begin','behave','behind','believe','below','belt',
		'bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike',
		'bind','biology','bird','birth','bitter','black','blade','blame','blanket','blast',
		'bleak','bless','blind','blood','blossom','blouse','blue','blur','blush','board',
		'boat','body','boil','bomb','bone','bonus','book','boost','border','boring',
		'borrow','boss','bottom','bounce','box','boy','bracket','brain','brand','brass',
		'brave','bread','breeze','brick','bridge','brief','bright','bring','brisk','broccoli',
		'broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo',
		'build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus',
		'business','busy','butter','buyer','buzz','cabbage','cabin','cable','cactus','cage',
		'cake','call','calm','camera','camp','can','canal','cancel','candy','cannon',
		'canoe','canvas','canyon','capable','capital','captain','car','carbon','card','cargo',
		'carpet','carry','cart','case','cash','casino','castle','casual','cat','catalog',
		'catch','category','cattle','caught','cause','caution','cave','ceiling','celery','cement',
		'census','century','cereal','certain','chair','chalk','champion','change','chaos','chapter',
		'charge','chase','chat','cheap','check','cheese','chef','cherry','chest','chicken',
		'chief','child','chimney','choice','choose','chronic','chuckle','chunk','churn','cigar',
		'cinnamon','circle','citizen','city','civil','claim','clap','clarify','claw','clay',
		'clean','clerk','clever','click','client','cliff','climb','clinic','clip','clock',
		'clog','close','cloth','cloud','clown','club','clump','cluster','clutch','coach',
		'coast','coconut','code','coffee','coil','coin','collect','color','column','combine',
		'come','comfort','comic','common','company','concert','conduct','confirm','congress','connect',
		'consider','control','convince','cook','cool','copper','copy','coral','core','corn',
		'correct','cost','cotton','couch','country','couple','course','cousin','cover','coyote',
		'crack','cradle','craft','cram','crane','crash','crater','crawl','crazy','cream',
		'credit','creek','crew','cricket','crime','crisp','critic','crop','cross','crouch',
		'crowd','crucial','cruel','cruise','crumble','crunch','crush','cry','crystal','cube',
		'culture','cup','cupboard','curious','current','curtain','curve','cushion','custom','cute',
		'cycle','dad','damage','damp','dance','danger','daring','dash','daughter','dawn',
		'day','deal','debate','debris','decade','december','decide','decline','decorate','decrease',
		'deer','defense','define','defy','degree','delay','deliver','demand','demise','denial',
		'dentist','deny','depart','depend','deposit','depth','deputy','derive','describe','desert',
		'design','desk','despair','destroy','detail','detect','develop','device','devote','diagram',
		'dial','diamond','diary','dice','diesel','diet','differ','digital','dignity','dilemma',
		'dinner','dinosaur','direct','dirt','disagree','discover','disease','dish','dismiss','disorder',
		'display','distance','divert','divide','divorce','dizzy','doctor','document','dog','doll',
		'dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft',
		'dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drip',
		'drive','drop','drum','dry','duck','dumb','dune','during','dust','dutch',
		'duty','dwarf','dynamic','eager','eagle','early','earn','earth','easily','east',
		'easy','echo','ecology','economy','edge','edit','educate','effort','egg','eight',
		'either','elbow','elder','electric','elegant','element','elephant','elevator','elite','else',
		'embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact',
		'end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy',
		'enlist','enough','enrich','enroll','ensure','enter','entire','entry','envelope','episode',
		'equal','equip','era','erase','erode','erosion','error','erupt','escape','essay',
		'essence','estate','eternal','ethics','evidence','evil','evoke','evolve','exact','example',
		'excess','exchange','excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile',
		'exist','exit','exotic','expand','expect','expire','explain','expose','express','extend',
		'extra','eye','eyebrow','fabric','face','faculty','fade','faint','faith','fall',
		'false','fame','family','famous','fan','fancy','fantasy','farm','fashion','fat',
		'fatal','father','fatigue','fault','favorite','feature','february','federal','fee','feed',
		'feel','female','fence','festival','fetch','fever','few','fiber','fiction','field',
		'figure','file','film','filter','final','find','fine','finger','finish','fire',
		'firm','first','fiscal','fish','fit','fitness','fix','flag','flame','flash',
		'flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid',
		'flush','fly','foam','focus','fog','foil','fold','follow','food','foot',
		'force','forest','forget','fork','fortune','forum','forward','fossil','foster','found',
		'fox','fragile','frame','frequent','fresh','friend','fringe','frog','front','frost',
		'frown','frozen','fruit','fuel','fun','funny','furnace','fury','future','gadget',
		'gain','galaxy','gallery','game','gap','garage','garbage','garden','garlic','garment',
		'gas','gasp','gate','gather','gauge','gaze','general','genius','genre','gentle',
		'genuine','gesture','ghost','giant','gift','giggle','ginger','giraffe','girl','give',
		'glad','glance','glare','glass','glide','glimpse','globe','gloom','glory','glove',
		'glow','glue','goat','goddess','gold','good','goose','gorilla','gospel','gossip',
		'govern','gown','grab','grace','grain','grant','grape','grass','gravity','great',
		'green','grid','grief','grit','grocery','group','grow','grunt','guard','guess',
		'guide','guilt','guitar','gun','gym','habit','hair','half','hammer','hamster',
		'hand','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard',
		'head','health','heart','heavy','hedgehog','height','hello','helmet','help','hen',
		'hero','hidden','high','hill','hint','hip','hire','history','hobby','hockey',
		'hold','hole','holiday','hollow','home','honey','hood','hope','horn','horror',
		'horse','hospital','host','hotel','hour','hover','hub','huge','human','humble',
		'humor','hundred','hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice',
		'icon','idea','identify','idle','ignore','ill','illegal','illness','image','imitate',
		'immense','immune','impact','impose','improve','impulse','inch','include','income','increase',
		'index','indicate','indoor','industry','infant','inflict','inform','inhale','inherit','initial',
		'inject','injury','inmate','inner','innocent','input','inquiry','insane','insect','inside',
		'inspire','install','intact','interest','into','invest','invite','involve','iron','island',
		'isolate','issue','item','ivory','jacket','jaguar','jar','jazz','jealous','jeans',
		'jelly','jewel','job','join','joke','journey','joy','judge','juice','jump',
		'jungle','junior','junk','just','kangaroo','keen','keep','ketchup','key','kick',
		'kid','kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi',
		'knee','knife','knock','know','lab','label','labor','ladder','lady','lake',
		'lamp','language','laptop','large','later','latin','laugh','laundry','lava','law',
		'lawn','lawsuit','layer','lazy','leader','leaf','learn','leave','lecture','left',
		'leg','legal','legend','leisure','lemon','lend','length','lens','leopard','lesson',
		'letter','level','liar','liberty','library','license','life','lift','light','like',
		'limb','limit','link','lion','liquid','list','little','live','lizard','load',
		'loan','lobster','local','lock','logic','lonely','long','loop','lottery','loud',
		'lounge','love','loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics',
		'machine','mad','magic','magnet','maid','mail','main','major','make','mammal',
		'man','manage','mandate','mango','mansion','manual','maple','marble','march','margin',
		'marine','market','marriage','mask','mass','master','match','material','math','matrix',
		'matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media',
		'melody','melt','member','memory','mention','menu','mercy','merge','merit','merry',
		'mesh','message','metal','method','middle','midnight','milk','million','mimic','mind',
		'minimum','minor','minute','miracle','mirror','misery','miss','mistake','mix','mixed',
		'mixture','mobile','model','modify','mom','moment','monitor','monkey','monster','month',
		'moon','moral','more','morning','mosquito','mother','motion','motor','mountain','mouse',
		'move','movie','much','muffin','mule','multiply','muscle','museum','mushroom','music',
		'must','mutual','myself','mystery','myth','naive','name','napkin','narrow','nasty',
		'nation','nature','near','neck','need','negative','neglect','neither','nephew','nerve',
		'nest','net','network','neutral','never','news','next','nice','night','noble',
		'noise','nominee','noodle','normal','north','nose','notable','note','nothing','notice',
		'novel','now','nuclear','number','nurse','nut','oak','obey','object','oblige',
		'obscure','observe','obtain','obvious','occur','ocean','october','odor','off','offer',
		'office','often','oil','okay','old','olive','olympic','omit','once','one',
		'onion','online','only','open','opera','opinion','oppose','option','orange','orbit',
		'orchard','order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor',
		'outer','output','outside','oval','oven','over','own','owner','oxygen','oyster',
		'ozone','pact','paddle','page','pair','palace','palm','panda','panel','panic',
		'panther','paper','parade','parent','park','parrot','party','pass','patch','path',
		'patient','patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant',
		'pelican','pen','penalty','pencil','people','pepper','perfect','permit','person','pet',
		'phone','photo','phrase','physical','piano','picnic','picture','piece','pig','pigeon',
		'pill','pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet',
		'plastic','plate','play','please','pledge','pluck','plug','plunge','poem','poet',
		'point','polar','pole','police','pond','pony','pool','popular','portion','position',
		'possible','post','potato','pottery','poverty','powder','power','practice','praise','predict',
		'prefer','prepare','present','pretty','prevent','price','pride','primary','print','priority',
		'prison','private','prize','problem','process','produce','profit','program','project','promote',
		'proof','property','prosper','protect','proud','provide','public','pudding','pull','pulp',
		'pulse','pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push',
		'put','puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz',
		'quote','rabbit','raccoon','race','rack','radar','radio','rail','rain','raise',
		'rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven',
		'raw','razor','ready','real','reason','rebel','rebuild','recall','receive','recipe',
		'record','recycle','reduce','reflect','reform','refuse','region','regret','regular','reject',
		'relax','release','relief','rely','remain','remember','remind','remove','render','renew',
		'rent','reopen','repair','repeat','replace','report','require','rescue','resemble','resist',
		'resource','response','result','retire','retreat','return','reunion','reveal','review','reward',
		'rhythm','rib','ribbon','rice','rich','ride','ridge','rifle','right','rigid',
		'ring','riot','ripple','risk','ritual','rival','river','road','roast','robot',
		'robust','rocket','romance','roof','rookie','room','rose','rotate','rough','round',
		'route','royal','rubber','rude','rug','rule','run','runway','rural','sad',
		'saddle','sadness','safe','sail','salad','salmon','salon','salt','salute','same',
		'sample','sand','satisfy','satoshi','sauce','sausage','save','say','scale','scan',
		'scare','scatter','scene','scheme','school','science','scissors','scorpion','scout','scrap',
		'screen','script','scrub','sea','search','season','seat','second','secret','section',
		'security','seed','seek','segment','select','sell','seminar','senior','sense','sentence',
		'series','service','session','settle','setup','seven','shadow','shaft','shallow','share',
		'shed','shell','sheriff','shield','shift','shine','ship','shiver','shock','shoe',
		'shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling',
		'sick','side','siege','sight','sign','silent','silk','silly','silver','similar',
		'simple','since','sing','siren','sister','situate','six','size','skate','sketch',
		'ski','skill','skin','skirt','skull','slab','slam','sleep','slender','slice',
		'slide','slight','slim','slogan','slot','slow','slush','small','smart','smile',
		'smoke','smooth','snack','snake','snap','sniff','snow','soap','soccer','social',
		'sock','soda','soft','solar','soldier','solid','solution','solve','someone','song',
		'soon','sorry','sort','soul','sound','soup','source','south','space','spare',
		'spatial','spawn','speak','special','speed','spell','spend','sphere','spice','spider',
		'spike','spin','spirit','split','spoil','sponsor','spoon','sport','spot','spray',
		'spread','spring','spy','square','squeeze','squirrel','stable','stadium','staff','stage',
		'stairs','stamp','stand','start','state','stay','steak','steel','stem','step',
		'stereo','stick','still','sting','stock','stomach','stone','stool','story','stove',
		'strategy','street','strike','strong','struggle','student','stuff','stumble','style','subject',
		'submit','subway','success','such','sudden','suffer','sugar','suggest','suit','summer',
		'sun','sunny','sunset','super','supply','supreme','sure','surface','surge','surprise',
		'surround','survey','suspect','sustain','swallow','swamp','swap','swarm','swear','sweet',
		'swift','swim','swing','switch','sword','symbol','symptom','syrup','system','table',
		'tackle','tag','tail','talent','talk','tank','tape','target','task','taste',
		'tattoo','taxi','teach','team','tell','ten','tenant','tennis','tent','term',
		'test','text','thank','that','theme','then','theory','there','they','thing',
		'this','thought','three','thrive','throw','thumb','thunder','ticket','tide','tiger',
		'tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco',
		'today','toddler','toe','together','toilet','token','tomato','tomorrow','tone','tongue',
		'tonight','tool','tooth','top','topic','topple','torch','tornado','tortoise','toss',
		'total','tourist','toward','tower','town','toy','track','trade','traffic','tragic',
		'train','transfer','trap','trash','travel','tray','treat','tree','trend','trial',
		'tribe','trick','trigger','trim','trip','trophy','trouble','truck','true','truly',
		'trumpet','trust','truth','try','tube','tuition','tumble','tuna','tunnel','turkey',
		'turn','turtle','twelve','twenty','twice','twin','twist','two','type','typical',
		'ugly','umbrella','unable','unaware','uncle','uncover','under','undo','unfair','unfold',
		'unhappy','uniform','unique','unit','universe','unknown','unlock','until','unusual','unveil',
		'update','upgrade','uphold','upon','upper','upset','urban','urge','usage','use',
		'used','useful','useless','usual','utility','vacant','vacuum','vague','valid','valley',
		'valve','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor',
		'venture','venue','verb','verify','version','very','vessel','veteran','viable','vibrant',
		'vicious','victory','video','view','village','vintage','violin','virtual','virus','visa',
		'visit','visual','vital','vivid','vocal','voice','void','volcano','volume','vote',
		'voyage','wage','wagon','wait','walk','wall','walnut','want','warfare','warm',
		'warrior','wash','wasp','waste','water','wave','way','wealth','weapon','wear',
		'weasel','weather','web','wedding','weekend','weird','welcome','west','wet','whale',
		'what','wheat','wheel','when','where','whip','whisper','wide','width','wife',
		'wild','will','win','window','wine','wing','wink','winner','winter','wire',
		'wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word',
		'work','world','worry','worth','wrap','wreck','wrestle','wrist','write','wrong',
		'yard','year','yellow','you','young','youth','zebra','zero','zone','zoo',
	);

	/**
	 * Generate a new pairing session.
	 * Returns array with 'words' (2 words for the device owner) and 'pairing_id' (internal).
	 */
	public static function generate_session() {
		// Clean up expired sessions first.
		self::cleanup_expired();

		$sessions = self::get_sessions();
		if ( count( $sessions ) >= self::MAX_ACTIVE ) {
			return new WP_Error( 'too_many', 'Too many active pairing sessions. Wait for existing ones to expire.' );
		}

		// Generate 5 random bytes (40 bits), use 33 bits for 3 BIP39 words.
		// Use hexdec(bin2hex(...)) instead of ord() << N to avoid integer
		// overflow on 32-bit PHP (and signed-int issues on 64-bit).
		$nonce = random_bytes( self::NONCE_BYTES );
		$bits = hexdec( bin2hex( $nonce ) ) & 0x1FFFFFFFF; // 33 bits
		$pairing_id = str_pad( dechex( $bits ), 9, '0', STR_PAD_LEFT ); // 9 hex chars from 33-bit value

		// Generate ECDH keypair (crypto_kx for X25519 + BLAKE2b key derivation).
		$kx_kp = sodium_crypto_kx_keypair();
		$server_kx_pk = sodium_crypto_kx_publickey( $kx_kp );
		$server_kx_sk = sodium_crypto_kx_secretkey( $kx_kp );

		$now = time();
		$sessions[ $pairing_id ] = array(
			'pairing_id'      => $pairing_id,
			'bits'            => $bits,
			'server_kx_pk'    => sodium_bin2hex( $server_kx_pk ),
			'server_kx_sk'    => sodium_bin2hex( $server_kx_sk ),
			'created_at'      => $now,
			'expires_at'      => $now + self::TTL_SECONDS,
			'status'          => 'waiting', // waiting | received | sas_ready | confirmed
			'client_kx_pk'    => '',
			'encrypted_phone_pk' => '',
			'sas_words'       => array(),
			'phone_pk'        => '',
		);

		$ok = update_option( self::OPTION, $sessions, false );
		if ( $ok === false ) {
			error_log( 'WC XMR Push Pairing: update_option failed during session generation.' );
			return new WP_Error( 'db_error', 'Failed to store pairing session.' );
		}

		$words = self::bits_to_words( $bits );

		WC_XMR_Push_Logger::log( 'pairing_create', array(
			'id'    => $pairing_id,
			'words' => implode( ' ', $words ),
		) );

		return array(
			'words'      => $words,
			'pairing_id' => $pairing_id,
		);
	}

	/**
	 * Handle GET request from device: ?pair=<pairing_id>
	 * Returns JSON with server's ephemeral public key.
	 */
	public static function handle_get( $pairing_id ) {
		$sessions = self::get_sessions();
		if ( ! isset( $sessions[ $pairing_id ] ) ) {
			return new WP_Error( 'not_found', 'Pairing session not found or expired.' );
		}

		$session = $sessions[ $pairing_id ];

		if ( ( $session['status'] ?? '' ) === 'rejected' ) {
			return new WP_Error( 'rejected', 'Pairing session was rejected.' );
		}

		if ( $session['expires_at'] < time() ) {
			unset( $sessions[ $pairing_id ] );
			update_option( self::OPTION, $sessions, false );
			return new WP_Error( 'expired', 'Pairing session expired.' );
		}

		if ( $session['status'] !== 'waiting' ) {
			return new WP_Error( 'already_used', 'This pairing session has already been used.' );
		}

		// Lock the GET to the first device - prevent multiple devices from
		// fetching the server's ephemeral key.  Only the device that did the
		// GET can proceed to POST (handle_post accepts 'claimed').
		// Re-read the session right before writing so a concurrent request
		// that already claimed it can't be overwritten by a stale copy
		// (WordPress options are not transactional - this closes the common
		// read-modify-write race window).
		$fresh = self::get_sessions();
		if ( ! isset( $fresh[ $pairing_id ] ) || ( $fresh[ $pairing_id ]['status'] ?? '' ) !== 'waiting' ) {
			return new WP_Error( 'already_used', 'This pairing session has already been used.' );
		}
		$session = $fresh[ $pairing_id ];
		$session['status'] = 'claimed';
		$session['claimed_at'] = time();
		$sessions[ $pairing_id ] = $session;
		update_option( self::OPTION, $sessions, false );

		WC_XMR_Push_Logger::log( 'pairing_get', array( 'id' => $pairing_id ) );

		return array(
			'pairing_id'    => $pairing_id,
			'server_kx_pk'  => $session['server_kx_pk'],
			'kx_version'    => 'xmr-push-kx-v1',
		);
	}

	/**
	 * Handle POST from device: client sends its ephemeral pk + encrypted device pk.
	 * Body: { pairing_id, client_kx_pk, encrypted_phone_pk }
	 */
	public static function handle_post( $data ) {
		$pairing_id         = $data['pairing_id'] ?? '';
		$client_kx_pk_hex   = $data['client_kx_pk'] ?? '';
		$encrypted_phone_pk = $data['encrypted_phone_pk'] ?? '';
		$kx_version         = $data['kx_version'] ?? '';

		if ( $pairing_id === '' || $client_kx_pk_hex === '' || $encrypted_phone_pk === '' ) {
			return new WP_Error( 'missing_fields', 'Missing required fields.' );
		}

		// Protocol version check: the device must declare the same kx_version
		// the server returned in handle_get. If missing or mismatched, the
		// device is running an incompatible daemon version.
		if ( $kx_version !== 'xmr-push-kx-v1' ) {
			return new WP_Error(
				'kx_mismatch',
				'Protocol version mismatch: device sent "' . $kx_version . '", server expects "xmr-push-kx-v1". '
				. 'Update the device daemon to the latest version.'
			);
		}

		$sessions = self::get_sessions();
		if ( ! isset( $sessions[ $pairing_id ] ) ) {
			return new WP_Error( 'not_found', 'Pairing session not found.' );
		}

		$session = &$sessions[ $pairing_id ];

		if ( $session['expires_at'] < time() ) {
			unset( $sessions[ $pairing_id ] );
			update_option( self::OPTION, $sessions, false );
			return new WP_Error( 'expired', 'Pairing session expired.' );
		}

		if ( $session['status'] !== 'waiting' && $session['status'] !== 'claimed' ) {
			return new WP_Error( 'already_used', 'Session already used.' );
		}

		// Hard cap on POST attempts per session (xmr.txt #4): an attacker with
		// the pairing code must not be able to grind ciphertexts against a live
		// session for the full 5-minute window. After 3 failed/useless POSTs the
		// session self-destructs (status 'rejected').
		$post_attempts = (int) ( $session['post_attempts'] ?? 0 ) + 1;
		if ( $post_attempts > 3 ) {
			$session['status'] = 'rejected';
			unset( $session['server_kx_sk'] );
			$sessions[ $pairing_id ] = $session;
			update_option( self::OPTION, $sessions, false );
			WC_XMR_Push_Logger::log( 'pairing_rejected', array( 'id' => $pairing_id, 'reason' => 'attempt_cap' ) );
			return new WP_Error( 'too_many_attempts', 'Too many pairing attempts - session revoked.' );
		}
		$session['post_attempts'] = $post_attempts;

		// Validate client_kx_pk format (64 hex chars = 32 bytes).
		if ( ! preg_match( '/^[0-9a-fA-F]{64}$/', $client_kx_pk_hex ) ) {
			return new WP_Error( 'bad_pk', 'Invalid client public key format.' );
		}

		$client_kx_pk = sodium_hex2bin( $client_kx_pk_hex );
		$server_kx_pk = sodium_hex2bin( $session['server_kx_pk'] );
		$server_kx_sk = sodium_hex2bin( $session['server_kx_sk'] );

		// Compute session keys using a custom KDF (NOT crypto_kx_*_session_keys).
		// sodium_compat and native libsodium hash the ECDH output in different
		// orders, producing incompatible session keys.  We use crypto_scalarmult
		// directly (which both agree on) and derive keys with BLAKE2b.
		// Canonical ordering of public keys ensures both sides derive identical keys.
		$shared_secret = sodium_crypto_scalarmult( $server_kx_sk, $client_kx_pk );
		$pks = array( $server_kx_pk, $client_kx_pk );
		sort( $pks ); // canonical order
		$session_keys = sodium_crypto_generichash(
			$shared_secret . $pks[0] . $pks[1] . 'xmr-push-kx-v1',
			'',
			64
		);
		$rx_key = substr( $session_keys, 0, 32 );
		$tx_key = substr( $session_keys, 32, 32 );

		// Decrypt the device's Ed25519 public key NOW so all ephemeral key
		// material can be zeroized before the session is persisted
		// (xmr.txt #5: the private scalar must not outlive the ECDH exchange).
		// The Python daemon sends URL-safe base64 with '=' padding stripped
		// (base64.urlsafe_b64encode(...).rstrip('=')); sodium_base642bin()
		// with an empty ignore string REQUIRES padding. Normalize a COPY for
		// decoding - the original unpadded string is fed verbatim into the
		// SAS / paired-secret transcripts below, and the daemon hashes the
		// same unpadded ASCII, so it must stay untouched.
		$b64_for_decode = rtrim( (string) $encrypted_phone_pk, "=" );
		if ( strlen( $b64_for_decode ) % 4 !== 0 ) {
			$b64_for_decode .= str_repeat( '=', 4 - ( strlen( $b64_for_decode ) % 4 ) );
		}
		try {
			$encrypted_raw = @sodium_base642bin( $b64_for_decode, SODIUM_BASE64_VARIANT_URLSAFE, '' );
		} catch ( Throwable $e ) {
			// Modern libsodium throws SodiumException on invalid base64;
			// older builds return false. Either way, degrade to a clean
			// pairing failure instead of a fatal.
			$encrypted_raw = false;
		}
		if ( ! $encrypted_raw || strlen( $encrypted_raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return new WP_Error( 'bad_ciphertext', 'Invalid encrypted device key.' );
		}
		$nonce      = substr( $encrypted_raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$ciphertext = substr( $encrypted_raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$phone_pk_hex = sodium_crypto_secretbox_open( $ciphertext, $nonce, $rx_key );
		if ( $phone_pk_hex === false || ! preg_match( '/^[0-9a-fA-F]{64}$/', $phone_pk_hex ) ) {
			return new WP_Error( 'decrypt_fail', 'Failed to decrypt device public key.' );
		}

		// Derive SAS = crypto_generichash(sorted(rx,tx) || pairing_id || encrypted_phone_pk || "xmr-push-pairing-v1")
		// xmr.txt #2/#8: binding the encrypted device pk into the SAS transcript
		// makes the human SAS check confirm *this specific device's authorized
		// key*, not merely "some device completed ECDH". It also counters the
		// non-contributory-KEX class: the full transcript (both pks, the
		// pairing id, and the ciphertext being authorized) feeds the KDF.
		$k1 = $rx_key;
		$k2 = $tx_key;
		if ( strcmp( $rx_key, $tx_key ) > 0 ) {
			$k1 = $tx_key;
			$k2 = $rx_key;
		}
		$sas_hash = sodium_crypto_generichash(
			$k1 . $k2 . $pairing_id . $encrypted_phone_pk . 'xmr-push-pairing-v1',
			'',
			32
		);
		// Use first 33 bits of SAS hash for 3 BIP39 words.
		// Use hexdec(bin2hex(...)) instead of ord() << N to avoid integer
		// overflow on 32-bit PHP (and signed-int issues on 64-bit).
		$sas_bits = hexdec( bin2hex( substr( $sas_hash, 0, 5 ) ) ) & 0x1FFFFFFFF;
		$sas_words = self::bits_to_words( $sas_bits );

		// Unification with the shared-secret path (xmr.txt): derive the SAME
		// shared secret the device will use for payload encryption, from the
		// same transcript. On confirm() it becomes wc_xmr_push_secret so the
		// device daemon can launch with a paired secret and no separate manual
		// copy. Both sides compute this identically.
		$paired_secret = sodium_crypto_generichash(
			$k1 . $k2 . $pairing_id . $encrypted_phone_pk . 'xmr-push-paired-secret-v1',
			'',
			32
		);

		// Zeroize ALL ephemeral key material now that ECDH + decrypt + KDFs
		// are done. The session only keeps the device's (public) pk, the SAS
		// words, and the derived paired secret (needed at confirm time).
		WC_XMR_Push_Crypto::safe_memzero( $server_kx_sk );
		WC_XMR_Push_Crypto::safe_memzero( $shared_secret );
		WC_XMR_Push_Crypto::safe_memzero( $rx_key );
		WC_XMR_Push_Crypto::safe_memzero( $tx_key );
		WC_XMR_Push_Crypto::safe_memzero( $session_keys );

		// Store in session (rx_key / server_kx_sk are NO LONGER persisted -
		// the device pk was already decrypted above).
		$session['status']             = 'sas_ready';
		$session['client_kx_pk']       = $client_kx_pk_hex;
		$session['encrypted_phone_pk'] = $encrypted_phone_pk;
		$session['sas_words']          = $sas_words;
		$session['phone_pk']           = $phone_pk_hex;
		$session['paired_secret']      = sodium_bin2hex( $paired_secret );
		WC_XMR_Push_Crypto::safe_memzero( $paired_secret );
		unset( $session['server_kx_sk'] );

		$ok = update_option( self::OPTION, $sessions, false );
		if ( $ok === false ) {
			error_log( 'WC XMR Push Pairing: update_option failed during handle_post.' );
			return new WP_Error( 'db_error', 'Failed to update session.' );
		}

		WC_XMR_Push_Logger::log( 'pairing_sas', array(
			'id'    => $pairing_id,
			'sas'   => implode( ' ', $sas_words ),
		) );

		return array(
			'status'    => 'sas_ready',
			'sas_words' => $sas_words,
		);
	}

	/**
	 * Admin confirms the SAS words match. Authorizes the device pk that was
	 * decrypted during handle_post (ephemeral keys are long gone).
	 */
	public static function confirm( $pairing_id ) {
		$sessions = self::get_sessions();
		if ( ! isset( $sessions[ $pairing_id ] ) ) {
			return new WP_Error( 'not_found', 'Pairing session not found.' );
		}

		$session = $sessions[ $pairing_id ];

		if ( $session['status'] !== 'sas_ready' ) {
			return new WP_Error( 'bad_state', 'Pairing session is not ready for confirmation. Wait for the device to connect.' );
		}

		if ( $session['expires_at'] < time() ) {
			unset( $sessions[ $pairing_id ] );
			update_option( self::OPTION, $sessions, false );
			return new WP_Error( 'expired', 'Pairing session expired.' );
		}

		// The device pk was already decrypted in handle_post (ephemeral keys
		// zeroized immediately after) - use the stored value.
		$phone_pk_hex = strtolower( $session['phone_pk'] ?? '' );
		if ( ! preg_match( '/^[0-9a-fA-F]{64}$/', $phone_pk_hex ) ) {
			unset( $sessions[ $pairing_id ] );
			update_option( self::OPTION, $sessions, false );
			return new WP_Error( 'bad_phone_pk', 'Pairing session is missing the device public key.' );
		}

		// Unification (xmr.txt): promote the paired secret derived during
		// handle_post to the plugin-wide shared secret, so the device daemon
		// can encrypt payloads with the same key it derives locally - no
		// manual secret copy needed. A manually-set secret always wins.
		if ( ! empty( $session['paired_secret'] ) && ! get_option( 'wc_xmr_push_secret_manual' ) ) {
			// Store through the same at-rest encryption envelope the settings
			// sanitize path (wc_xmr_push_sanitize_secret) applies - never
			// persist plaintext hex when crypto is enabled. Fail-open to
			// plaintext with a logged warning if encryption fails.
			$secret = (string) $session['paired_secret'];
			if ( class_exists( 'WC_XMR_Crypto' ) && WC_XMR_Crypto::enabled() ) {
				try { $enc = WC_XMR_Crypto::encrypt( $secret ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: WC_XMR_Crypto::encrypt threw during pairing secret promotion: ' . $e->getMessage() ); $enc = false; }
				if ( is_string( $enc ) && $enc !== '' ) {
					$secret = $enc;
				} else {
					error_log( 'WC XMR Push: WC_XMR_Crypto::encrypt returned empty/false during pairing secret promotion - storing plaintext fail-open.' );
				}
			}
			update_option( 'wc_xmr_push_secret', $secret, false );
			update_option( 'wc_xmr_push_secret_source', 'paired', false );
		}

		// Authorize the device.
		if ( class_exists( 'WC_XMR_Push_Sig' ) ) {
			$result = WC_XMR_Push_Sig::add_phone( $phone_pk_hex, 'Paired via words (' . gmdate( 'Y-m-d H:i' ) . ')' );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		// Clean up the session.
		unset( $sessions[ $pairing_id ] );
		update_option( self::OPTION, $sessions, false );

		WC_XMR_Push_Logger::log( 'pairing_confirm', array(
			'id' => $pairing_id,
			'pk' => substr( $phone_pk_hex, 0, 16 ) . '...',
		) );

		return array(
			'status'       => 'confirmed',
			'phone_pk'     => $phone_pk_hex,
		);
	}

	/**
	 * Reject a pairing session whose SAS words did NOT match.
	 * Tears the session down immediately (status 'rejected', otk appended)
	 * instead of leaving it live for the full TTL, so a claimed-but-rejected
	 * session stops being attackable right away.
	 */
	public static function reject( $pairing_id ) {
		$sessions = self::get_sessions();
		if ( ! isset( $sessions[ $pairing_id ] ) ) {
			return new WP_Error( 'not_found', 'Pairing session not found.' );
		}
		$sessions[ $pairing_id ]['status'] = 'rejected';
		$sessions[ $pairing_id ]['rejected_at'] = time();
		unset( $sessions[ $pairing_id ]['server_kx_sk'] );
		unset( $sessions[ $pairing_id ]['paired_secret'] );
		$ok = update_option( self::OPTION, $sessions, false );
		if ( $ok === false ) {
			error_log( 'WC XMR Push Pairing: update_option failed during reject.' );
			return new WP_Error( 'db_error', 'Failed to update session.' );
		}
		WC_XMR_Push_Logger::log( 'pairing_rejected', array( 'id' => $pairing_id, 'reason' => 'sas_mismatch' ) );
		return true;
	}

	/**
	 * Cancel/delete a pairing session.
	 */
	public static function cancel( $pairing_id ) {
		$sessions = self::get_sessions();
		if ( isset( $sessions[ $pairing_id ] ) ) {
			unset( $sessions[ $pairing_id ] );
			update_option( self::OPTION, $sessions, false );
		}
		return true;
	}

	/**
	 * Get a specific session by ID.
	 */
	public static function get_session( $pairing_id ) {
		$sessions = self::get_sessions();
		return $sessions[ $pairing_id ] ?? null;
	}

	/**
	 * Get all active sessions.
	 */
	public static function get_sessions() {
		$sessions = get_option( self::OPTION, array() );
		if ( ! is_array( $sessions ) ) return array();
		return $sessions;
	}

	/**
	 * Remove expired sessions.
	 */
	public static function cleanup_expired() {
		$sessions = self::get_sessions();
		$now = time();
		$changed = false;
		foreach ( $sessions as $id => $session ) {
			if ( $session['expires_at'] < $now ) {
				unset( $sessions[ $id ] );
				$changed = true;
			}
		}
		if ( $changed ) {
			update_option( self::OPTION, $sessions, false );
		}
	}

	/**
	 * Convert 33 bits to 3 BIP39 words.
	 */
	public static function bits_to_words( $bits ) {
		$bits = $bits & 0x1FFFFFFFF; // 33 bits
		$idx1 = ( $bits >> 22 ) & 0x7FF;
		$idx2 = ( $bits >> 11 ) & 0x7FF;
		$idx3 = $bits & 0x7FF;
		return array( self::WORDLIST[ $idx1 ], self::WORDLIST[ $idx2 ], self::WORDLIST[ $idx3 ] );
	}

	/**
	 * Convert 3 BIP39 words back to 33 bits.
	 */
	public static function words_to_bits( $word1, $word2, $word3 ) {
		$word1 = strtolower( trim( $word1 ) );
		$word2 = strtolower( trim( $word2 ) );
		$word3 = strtolower( trim( $word3 ) );
		$idx1 = array_search( $word1, self::WORDLIST, true );
		$idx2 = array_search( $word2, self::WORDLIST, true );
		$idx3 = array_search( $word3, self::WORDLIST, true );
		if ( $idx1 === false || $idx2 === false || $idx3 === false ) return false;
		return ( ( $idx1 & 0x7FF ) << 22 ) | ( ( $idx2 & 0x7FF ) << 11 ) | ( $idx3 & 0x7FF );
	}

	/**
	 * Find a pairing session by the 33-bit code (from 3 words).
	 */
	public static function find_by_bits( $bits ) {
		$sessions = self::get_sessions();
		foreach ( $sessions as $id => $session ) {
			if ( ( $session['bits'] ?? -1 ) === $bits ) {
				return $session;
			}
		}
		return null;
	}
}