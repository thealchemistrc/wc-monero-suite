#!/usr/bin/env python3
"""
Full E2E test: inserts a pairing session directly into WordPress DB,
then tests the GET and POST endpoints.

Usage: python test_full_e2e.py
"""

import subprocess, json, sys, hashlib, secrets, base64, os, time

WP_URL = "http://localhost/shop"

BIP39 = [
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
]

def bits_to_words(bits):
    w1 = (bits >> 11) & 0x7FF
    w2 = bits & 0x7FF
    return [BIP39[w1], BIP39[w2]]

def bits_to_words_3(bits):
    """Convert 33-bit value to 3 BIP39 words (matching PHP server)."""
    w1 = (bits >> 22) & 0x7FF
    w2 = (bits >> 11) & 0x7FF
    w3 = bits & 0x7FF
    return [BIP39[w1], BIP39[w2], BIP39[w3]]

def compute_sas(rx_key, tx_key, pairing_id, encrypted_phone_pk_b64):
    """Derive SAS words from ECDH session keys, matching PHP server derivation.
    
    PHP server uses:
      $sas_hash = crypto_generichash(
          $k1 . $k2 . $pairing_id . $encrypted_phone_pk . 'xmr-push-pairing-v1'
      );
      $sas_bits = hexdec(bin2hex(substr($sas_hash, 0, 5))) & 0x1FFFFFFFF;  // 33 bits
      $sas_words = bits_to_words($sas_bits);  // 3 BIP39 words
    
    IMPORTANT: Keys are sorted (canonical order) before hashing so both sides
    produce identical SAS words regardless of rx/tx swap between server and client.
    """
    from nacl.hash import generichash
    # Sort keys for canonical ordering (both sides agree on SAS)
    k1, k2 = (rx_key, tx_key) if rx_key < tx_key else (tx_key, rx_key)
    context = b'xmr-push-pairing-v1'
    sas_hash = bytes.fromhex(generichash(k1 + k2 + pairing_id.encode('ascii') + encrypted_phone_pk_b64.encode('ascii') + context, digest_size=32).decode('ascii'))
    # Use first 33 bits of SAS hash for 3 BIP39 words (matching PHP).
    # PHP: hexdec(bin2hex(substr($sas_hash, 0, 5))) & 0x1FFFFFFFF
    # Takes 5 bytes (40 bits), converts to int, masks to 33 bits.
    bits = int.from_bytes(sas_hash[0:5], 'big') & 0x1FFFFFFFF
    return bits_to_words_3(bits)

def run_curl(*args):
    """Run curl.exe and return (stdout, http_code)."""
    cmd = ['curl.exe', '-s', '-o', '-', '-w', '\n%{http_code}'] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout.strip()
    parts = output.rsplit('\n', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return output, '0'

def find_wp_config():
    """Find wp-config.php and extract DB credentials."""
    paths = []
    env_path = os.environ.get('WP_CONFIG')
    if env_path:
        paths.append(env_path)
    # Common local dev layouts (suite repo at wp-content/plugins/<repo>, this file in <repo>/daemon).
    for rel in ('../../../../wp-config.php', '../../../wp-config.php'):
        paths.append(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), rel)))
    paths += [
        'C:/xampp/htdocs/shop/wp-config.php',
        'C:/wamp64/www/shop/wp-config.php',
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def parse_wp_config(path):
    """Parse DB credentials from wp-config.php."""
    with open(path, 'r') as f:
        content = f.read()
    
    import re
    # Use define( 'KEY', 'value' ) format - value is between single quotes
    db_name = re.search(r"define\(\s*'DB_NAME'\s*,\s*'([^']*)'", content)
    db_user = re.search(r"define\(\s*'DB_USER'\s*,\s*'([^']*)'", content)
    db_pass = re.search(r"define\(\s*'DB_PASSWORD'\s*,\s*'([^']*)'", content)
    db_host = re.search(r"define\(\s*'DB_HOST'\s*,\s*'([^']*)'", content)
    table_prefix = re.search(r"\$table_prefix\s*=\s*'([^']*)'", content)
    
    return {
        'name': db_name.group(1) if db_name else 'wordpress',
        'user': db_user.group(1) if db_user else 'root',
        'pass': db_pass.group(1) if db_pass else '',
        'host': db_host.group(1) if db_host else 'localhost',
        'prefix': table_prefix.group(1) if table_prefix else 'wp_',
    }

def insert_test_session(db_config):
    """Insert a test pairing session directly into the WordPress options table."""
    import nacl.bindings
    
    # Generate server ECDH keypair
    server_kx_pk, server_kx_sk = nacl.bindings.crypto_kx_keypair()
    server_kx_pk_hex = server_kx_pk.hex()
    server_kx_sk_hex = server_kx_sk.hex()
    
    # Generate pairing ID (9 hex chars, matching server's 33-bit format)
    bits = secrets.randbits(33)
    pairing_id = f"{bits:09x}"
    
    # Compute SAS words (placeholder - will be computed when client connects)
    # For now, store the server key
    session_data = {
        'pairing_id': pairing_id,
        'server_kx_pk': server_kx_pk_hex,
        'server_kx_sk': server_kx_sk_hex,
        'status': 'waiting',
        'created_at': int(time.time()),
        'expires_at': int(time.time()) + 300,
        'client_kx_pk': None,
        'phone_pk': None,
        'sas_words': None,
    }
    
    # PHP stores ALL sessions in a single option: wc_xmr_push_pairings
    # WordPress get_option() expects PHP-serialized data, NOT JSON!
    # We must use PHP serialization format.
    import phpserialize
    
    option_name = 'wc_xmr_push_pairings'
    
    def get_mysql_conn():
        try:
            import pymysql
            return pymysql.connect(
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['pass'],
                database=db_config['name'],
            )
        except ImportError:
            import mysql.connector
            return mysql.connector.connect(
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['pass'],
                database=db_config['name'],
            )
    
    conn = get_mysql_conn()
    cursor = conn.cursor()
    
    # Read existing sessions (may be PHP-serialized)
    cursor.execute(
        "SELECT option_value FROM `{}options` WHERE option_name = %s".format(db_config['prefix']),
        (option_name,)
    )
    row = cursor.fetchone()
    
    if row and row[0]:
        try:
            sessions = phpserialize.loads(row[0].encode('utf-8') if isinstance(row[0], str) else row[0])
        except:
            sessions = {}
        # Convert from phpserialize dict (bytes keys) to regular dict
        if isinstance(sessions, dict):
            sessions = {k.decode('utf-8') if isinstance(k, bytes) else k: v for k, v in sessions.items()}
    else:
        sessions = {}
    
    # Add our session
    sessions[pairing_id] = session_data
    
    # Write back as PHP-serialized
    new_value = phpserialize.dumps(sessions)
    cursor.execute(
        "INSERT INTO `{}options` (option_name, option_value, autoload) VALUES (%s, %s, 'no') "
        "ON DUPLICATE KEY UPDATE option_value = VALUES(option_value)".format(db_config['prefix']),
        (option_name, new_value)
    )
    conn.commit()
    cursor.close()
    conn.close()
    print(f"    [ok] Inserted session into DB option: {option_name}[{pairing_id}]")
    return pairing_id, server_kx_pk_hex, server_kx_sk_hex

def main():
    print("=" * 60)
    print("Full E2E Pairing Test")
    print("=" * 60)
    
    # Find WordPress config
    wp_config = find_wp_config()
    if not wp_config:
        print("ERROR: Cannot find wp-config.php")
        print("Please specify the path manually or ensure WordPress is installed.")
        sys.exit(1)
    
    print(f"\n[0] Found wp-config: {wp_config}")
    db_config = parse_wp_config(wp_config)
    print(f"    DB: {db_config['user']}@{db_config['host']}/{db_config['name']}")
    
    # Insert test session
    print("\n[1] Inserting test pairing session...")
    pairing_id, server_kx_pk_hex, server_kx_sk_hex = insert_test_session(db_config)
    
    if not pairing_id:
        print("ERROR: Could not insert test session.")
        sys.exit(1)
    
    print(f"    pairing_id: {pairing_id}")
    print(f"    server_kx_pk: {server_kx_pk_hex[:40]}...")
    
    # Step 2: GET server's ephemeral public key via HTTP
    print(f"\n[2] GET ?pair={pairing_id} ...")
    body, code = run_curl(f'{WP_URL}/?pair={pairing_id}')
    print(f"    HTTP {code}")
    
    if code != '200':
        print(f"    ERROR: {body[:300]}")
        sys.exit(1)
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(f"    Non-JSON response: {body[:200]}")
        sys.exit(1)
    
    if 'error' in data:
        print(f"    ERROR: {data['error']}")
        sys.exit(1)
    
    returned_kx_pk = data['server_kx_pk']
    kx_version = data.get('kx_version', '')
    print(f"    server_kx_pk from endpoint: {returned_kx_pk[:40]}...")
    print(f"    kx_version from endpoint: {kx_version}")
    
    if returned_kx_pk != server_kx_pk_hex:
        print(f"    [x] MISMATCH! Expected {server_kx_pk_hex[:40]}...")
        sys.exit(1)
    print("    [ok] Key matches!")
    
    if kx_version != 'xmr-push-kx-v1':
        print(f"    [x] kx_version mismatch! Expected 'xmr-push-kx-v1', got '{kx_version}'")
        sys.exit(1)
    print("    [ok] kx_version matches!")
    
    # Step 3: Device generates its own ECDH keypair
    print("\n[3] Generating device ECDH keypair...")
    import nacl.bindings
    client_kx_pk, client_kx_sk = nacl.bindings.crypto_kx_keypair()
    client_kx_pk_hex = client_kx_pk.hex()
    print(f"    client_kx_pk: {client_kx_pk_hex[:40]}...")
    
    # Step 4: Derive shared secret (custom KDF matching PHP)
    print("\n[4] Deriving ECDH session keys...")
    server_kx_pk = bytes.fromhex(server_kx_pk_hex)
    server_kx_sk = bytes.fromhex(server_kx_sk_hex)
    # Use nacl.bindings.crypto_generichash (raw bytes) NOT nacl.hash.generichash
    # which may return hex-encoded output depending on PyNaCl version.
    from nacl.hash import generichash
    
    # Compute shared secret BOTH ways to verify ECDH commutativity
    shared_secret_client = nacl.bindings.crypto_scalarmult(client_kx_sk, server_kx_pk)
    shared_secret_server = nacl.bindings.crypto_scalarmult(server_kx_sk, client_kx_pk)
    print(f"    shared_secret (client): {shared_secret_client.hex()[:40]}...")
    print(f"    shared_secret (server): {shared_secret_server.hex()[:40]}...")
    if shared_secret_client != shared_secret_server:
        print("    [x] ECDH commutativity FAILED! Shared secrets differ.")
        sys.exit(1)
    print("    [ok] ECDH shared secrets match (commutativity OK)")
    shared_secret = shared_secret_client
    
    # Canonical ordering of public keys (matching PHP sort)
    pks = sorted([server_kx_pk, client_kx_pk])
    print(f"    pks[0] (sorted): {pks[0].hex()[:40]}...")
    print(f"    pks[1] (sorted): {pks[1].hex()[:40]}...")
    session_keys = bytes.fromhex(generichash(shared_secret + pks[0] + pks[1] + b'xmr-push-kx-v1', digest_size=64).decode('ascii'))
    rx_key = session_keys[0:32]
    tx_key = session_keys[32:64]
    print(f"    rx_key: {rx_key.hex()[:40]}...")
    print(f"    tx_key: {tx_key.hex()[:40]}...")
    
    # Step 5: Encrypt device's Ed25519 public key
    print("\n[5] Encrypting device public key...")
    
    # Generate device Ed25519 signing keypair
    phone_sk_seed = secrets.token_bytes(32)
    phone_pk, phone_sk_full = nacl.bindings.crypto_sign_seed_keypair(phone_sk_seed)
    phone_pk_hex = phone_pk.hex()
    print(f"    phone_pk: {phone_pk_hex[:40]}...")
    
    # Encrypt phone_pk HEX STRING (64 ASCII chars) with rx_key using crypto_secretbox.
    # The server expects the hex-encoded public key as plaintext, not raw 32 bytes:
    #   $phone_pk_hex = sodium_crypto_secretbox_open( ... );
    #   if ( ! preg_match( '/^[0-9a-fA-F]{64}$/', $phone_pk_hex ) ) { decrypt_fail }
    nonce = secrets.token_bytes(24)
    encrypted = nacl.bindings.crypto_secretbox(phone_pk_hex.encode('ascii'), nonce, rx_key)
    encrypted_b64 = base64.urlsafe_b64encode(nonce + encrypted).decode('ascii').rstrip('=')
    print(f"    encrypted_phone_pk (b64): {encrypted_b64[:60]}...")
    
    # Step 6: Compute SAS (must be after encryption, since server includes encrypted_phone_pk in transcript)
    print("\n[6] Computing SAS...")
    sas_words = compute_sas(rx_key, tx_key, pairing_id, encrypted_b64)
    print(f"    Client SAS: {sas_words[0]} {sas_words[1]} {sas_words[2]}")
    
    # Step 7: POST to server (include kx_version from GET response)
    print("\n[7] POST encrypted device key to server...")
    post_data = f'pairing_id={pairing_id}&client_kx_pk={client_kx_pk_hex}&encrypted_phone_pk={encrypted_b64}&kx_version={kx_version}'
    body, code = run_curl('-X', 'POST', '-d', post_data, f'{WP_URL}/')
    print(f"    HTTP {code}")
    
    if code != '200':
        print(f"    ERROR: {body[:300]}")
        sys.exit(1)
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(f"    Non-JSON response: {body[:200]}")
        sys.exit(1)
    
    if 'error' in data:
        print(f"    ERROR: {data['error']}")
        sys.exit(1)
    
    print(f"    Response: {json.dumps(data, indent=2)}")
    
    # Step 8: Verify SAS from server response
    if 'sas_words' in data:
        server_sas = data['sas_words']
        print(f"\n[8] Server SAS: {server_sas[0]} {server_sas[1]} {server_sas[2]}")
        print(f"    Client SAS: {sas_words[0]} {sas_words[1]} {sas_words[2]}")
        if server_sas == sas_words:
            print("    [ok] SAS MATCH! Pairing is secure.")
        else:
            print("    [x] SAS MISMATCH! DO NOT CONFIRM.")
    else:
        print("\n[8] No SAS in response")
    
    print("\n" + "=" * 60)
    print("E2E test complete!")
    print("=" * 60)

if __name__ == '__main__':
    main()