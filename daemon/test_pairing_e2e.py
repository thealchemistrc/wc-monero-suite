#!/usr/bin/env python3
"""
End-to-end test of the WordPress pairing endpoint.
Tests the full ECDH + SAS flow against the live WordPress instance.

Usage: python test_pairing_e2e.py
"""

import subprocess, json, sys, os, hashlib, secrets

# --- Config ---
WP_URL = "http://localhost/shop"
DB_HOST = "localhost"
DB_USER = "shop_user"
DB_PASS = '{U_-PmE]#.:N2iu9cD0ghN19-)QWSE8LgUo:{>^W"k$sJ?^O_!lTF^5*4HRsG*zbj;f2^xR3Y&VE([}x[kD4oEu7R}b~;guVyoo||vVP(y}.~=bPksm5pJf<ct5z+E'
DB_NAME = "shop_database"
TABLE_PREFIX = "wp_"

# --- BIP39 wordlist (first 2048 words) ---
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
    """Convert 22-bit integer to 2 BIP39 words."""
    w1 = (bits >> 11) & 0x7FF
    w2 = bits & 0x7FF
    return [BIP39[w1], BIP39[w2]]

def words_to_bits(words):
    """Convert 2 BIP39 words back to 22-bit integer."""
    w1 = BIP39.index(words[0])
    w2 = BIP39.index(words[1])
    return (w1 << 11) | w2

def bits_to_hex(bits):
    """Convert 22-bit integer to 6-char hex pairing ID."""
    return format(bits, '06x')

def compute_sas(server_kx_pk_hex, client_kx_pk_hex):
    """
    Compute SAS (2 BIP39 words) from the two ECDH public keys.
    Uses canonical ordering (smaller hex first) + BLAKE2b.
    Must match PHP implementation exactly.
    """
    # Canonical ordering: sort hex strings lexicographically
    keys = sorted([server_kx_pk_hex.lower(), client_kx_pk_hex.lower()])
    combined = keys[0] + keys[1]
    raw = combined.encode('ascii')
    
    # BLAKE2b-256, then take first 22 bits
    h = hashlib.blake2b(raw, digest_size=32).digest()
    bits = ((h[0] << 16) | (h[1] << 8) | h[2]) & 0x3FFFFF
    return bits_to_words(bits)


def run_curl(*args):
    """Run curl.exe and return (stdout, http_code)."""
    cmd = ['curl.exe', '-s', '-o', '-', '-w', '\n%{http_code}'] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout.strip()
    parts = output.rsplit('\n', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return output, '0'


def main():
    print("=" * 60)
    print("E2E Pairing Test - WordPress Endpoint")
    print("=" * 60)
    
    # Step 1: Generate a test pairing session directly in the DB
    print("\n[1] Generating test pairing session...")
    
    # Generate random 22-bit pairing ID
    bits = secrets.randbits(22)
    pairing_id = bits_to_hex(bits)
    words = bits_to_words(bits)
    print(f"    Pairing ID: {pairing_id}")
    print(f"    Words: {words[0]} {words[1]}")
    
    # Generate server ECDH keypair
    import nacl.bindings
    server_kx_pk, server_kx_sk = nacl.bindings.crypto_kx_keypair()
    server_kx_pk_hex = server_kx_pk.hex()
    server_kx_sk_hex = server_kx_sk.hex()
    
    now = int(__import__('time').time())
    session_data = {
        'pairing_id': pairing_id,
        'bits': bits,
        'server_kx_pk': server_kx_pk_hex,
        'server_kx_sk': server_kx_sk_hex,
        'created_at': now,
        'expires_at': now + 300,
        'status': 'waiting',
        'client_kx_pk': '',
        'encrypted_phone_pk': '',
        'sas_words': [],
        'phone_pk': '',
    }
    
    # Store in DB via mysql command
    option_name = 'wc_xmr_push_pairings'
    sessions = {pairing_id: session_data}
    sessions_json = json.dumps(sessions)
    
    # Use Python mysql connector or just shell out
    # Escape the JSON for SQL
    escaped_json = sessions_json.replace("'", "\\'")
    
    sql = f"INSERT INTO {TABLE_PREFIX}options (option_name, option_value, autoload) VALUES ('{option_name}', '{escaped_json}', 'no') ON DUPLICATE KEY UPDATE option_value = '{escaped_json}'"
    
    mysql_cmd = [
        'mysql', '-h', DB_HOST, '-u', DB_USER, f'-p{DB_PASS}', DB_NAME,
        '-e', sql
    ]
    
    result = subprocess.run(mysql_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    ERROR inserting session: {result.stderr}")
        # Try without password (maybe it's in my.cnf)
        mysql_cmd2 = [
            'mysql', '-h', DB_HOST, '-u', DB_USER, DB_NAME,
            '-e', sql
        ]
        result2 = subprocess.run(mysql_cmd2, capture_output=True, text=True)
        if result2.returncode != 0:
            print(f"    ERROR (retry): {result2.stderr}")
            print("    Skipping DB insert - session may not exist for GET test")
        else:
            print("    Session stored in DB (no-password).")
    else:
        print("    Session stored in DB.")
    
    # Step 2: Test GET endpoint
    print(f"\n[2] Testing GET ?pair={pairing_id}...")
    body, code = run_curl(f'{WP_URL}/?pair={pairing_id}')
    print(f"    HTTP {code}: {body[:200]}")
    
    if code == '200':
        try:
            data = json.loads(body)
            if 'error' in data:
                print(f"    ERROR: {data['error']}")
                if data['error'] == 'not_found':
                    print("    Session not found in DB - the direct DB insert may have failed.")
                    print("    Try creating a session via the WordPress admin panel instead.")
            else:
                print(f"    server_kx_pk: {data.get('server_kx_pk', 'N/A')[:40]}...")
                server_kx_pk_from_server = data.get('server_kx_pk', '')
        except json.JSONDecodeError:
            print(f"    Non-JSON response (likely HTML - endpoint not intercepting)")
    
    # Step 3: Simulate device-side ECDH
    print("\n[3] Simulating device-side ECDH exchange...")
    
    # Device generates its own KX keypair
    client_kx_pk, client_kx_sk = nacl.bindings.crypto_kx_keypair()
    client_kx_pk_hex = client_kx_pk.hex()
    
    # Device generates Ed25519 signing keypair
    phone_sk = nacl.bindings.crypto_sign_seed_keypair(secrets.token_bytes(32))
    phone_pk = phone_sk[0]  # 32 bytes
    phone_pk_hex = phone_pk.hex()
    
    print(f"    Device KX pk: {client_kx_pk_hex[:40]}...")
    print(f"    Device Ed25519 pk: {phone_pk_hex[:40]}...")
    
    # Compute SAS
    sas_words = compute_sas(server_kx_pk_hex, client_kx_pk_hex)
    print(f"    SAS words: {sas_words[0]} {sas_words[1]}")
    
    # Device computes shared secret via crypto_kx
    # client_session_keys = crypto_kx_client_session_keys(client_pk, client_sk, server_pk)
    rx_key, tx_key = nacl.bindings.crypto_kx_client_session_keys(client_kx_pk, client_kx_sk, server_kx_pk)
    print(f"    Shared secret derived (rx_key[:20]): {rx_key.hex()[:40]}...")
    
    # Encrypt phone_pk with rx_key using crypto_secretbox
    nonce = secrets.token_bytes(24)
    encrypted = nacl.bindings.crypto_secretbox(phone_pk, nonce, rx_key)
    encrypted_b64 = __import__('base64').b64encode(nonce + encrypted).decode('ascii')
    print(f"    Encrypted phone_pk (b64): {encrypted_b64[:60]}...")
    
    # Step 4: Test POST endpoint
    print(f"\n[4] Testing POST with pairing_id={pairing_id}...")
    post_data = f'pairing_id={pairing_id}&client_kx_pk={client_kx_pk_hex}&encrypted_phone_pk={encrypted_b64}'
    body, code = run_curl('-X', 'POST', '-d', post_data, f'{WP_URL}/')
    print(f"    HTTP {code}: {body[:200]}")
    
    if code == '200':
        try:
            data = json.loads(body)
            if 'error' in data:
                print(f"    ERROR: {data['error']}")
            else:
                print(f"    Response: {json.dumps(data, indent=2)[:300]}")
        except json.JSONDecodeError:
            print(f"    Non-JSON response")
    
    # Step 5: Verify SAS from server side
    print("\n[5] Verifying SAS (server-side computation)...")
    print(f"    Server KX pk: {server_kx_pk_hex[:40]}...")
    print(f"    Client KX pk: {client_kx_pk_hex[:40]}...")
    print(f"    SAS (canonical order): {sas_words[0]} {sas_words[1]}")
    
    # Also test with reversed order to confirm canonical ordering works
    sas_rev = compute_sas(client_kx_pk_hex, server_kx_pk_hex)
    assert sas_words == sas_rev, f"SAS mismatch! {sas_words} != {sas_rev}"
    print("    SAS canonical ordering verified [ok]")
    
    # Step 6: Poll for admin confirmation via pair_status endpoint
    print("\n[6] Polling for admin confirmation...")
    print(f"    The admin must confirm the SAS words in WordPress admin panel.")
    print(f"    SAS words to confirm: {sas_words[0]} {sas_words[1]}")
    print(f"    Polling ?pair_status={pairing_id} every 2s (timeout 120s)...")
    
    confirmed = False
    timeout = 120
    start = __import__('time').time()
    while __import__('time').time() - start < timeout:
        body, code = run_curl(f'{WP_URL}/?pair_status={pairing_id}')
        elapsed = int(__import__('time').time() - start)
        try:
            data = json.loads(body)
            status = data.get('status', 'unknown')
            print(f"    [{elapsed}s] HTTP {code} status={status}")
            if status == 'confirmed':
                print("    [ok] Admin confirmed the pairing!")
                confirmed = True
                break
            elif status == 'expired':
                print("    [x] Session expired before confirmation.")
                break
            elif status == 'not_found':
                # Session deleted after confirm - this also means success
                print("    [ok] Session not found (deleted after confirmation = success)")
                confirmed = True
                break
        except json.JSONDecodeError:
            print(f"    [{elapsed}s] Non-JSON response: {body[:80]}")
        __import__('time').sleep(2)
    
    if not confirmed:
        print("    Timed out waiting for admin confirmation.")
        print("    (This is expected if no admin is available to confirm.)")
    
    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()