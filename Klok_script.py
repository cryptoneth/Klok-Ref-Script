import json
import os
import requests
import secrets
import time
import random
import subprocess
from datetime import datetime, timezone
from colorama import init, Fore, Style
import uuid
from dotenv import load_dotenv
from web3.auto import w3
from eth_account import Account
from eth_account.messages import encode_defunct

# Inizializza colorama
init()

# Carica le variabili d'ambiente
load_dotenv()
RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
if not RECAPTCHA_SITE_KEY:
    raise ValueError("RECAPTCHA_SITE_KEY non impostata nel file .env")
# RECAPTCHA_SECRET_KEY è opzionale, poiché Klokapp.ai probabilmente verifica i token lato server

# Inizializza Web3
w3 = w3

# Opzioni di modello per le chat
MODELS = [
    "llama-3.3-70b-instruct",
    "deepseek-r1",
    "gpt-4o-mini"
]

# User agent casuali per le richieste
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Edge/133.0.2623.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Brave/133.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
]

def print_banner():
    """Mostra il banner dello script."""
    print(rf"""
{Fore.CYAN}
Kelliark | Klok.ai Auto Referral and Chat Bot{Style.RESET_ALL}
""")

def log_message(wallet_count, address, ip, ref_code, status="info", message=""):
    """Registra i messaggi con formattazione colorata."""
    color_map = {
        "success": Fore.GREEN + Style.BRIGHT,
        "error": Fore.RED + Style.BRIGHT,
        "warning": Fore.YELLOW + Style.BRIGHT,
        "info": Fore.CYAN + Style.BRIGHT,
        "process": Fore.MAGENTA + Style.BRIGHT,
        "address": Fore.WHITE + Style.BRIGHT,
        "ip": Fore.BLUE + Style.BRIGHT,
        "referral": Fore.YELLOW + Style.NORMAL,
        "chat": Fore.GREEN + Style.NORMAL
    }

    if status == "process":
        print(f"\n{color_map['process']}━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"Generazione Wallet #{wallet_count}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
    else:
        print(f"{color_map[status]}━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if status == "success":
            print(f"Wallet #{wallet_count} Generato con Successo!")
        elif status == "error":
            print(f"Wallet #{wallet_count} Fallito!")
        print(f"{color_map['address']}Indirizzo: {address}")
        print(f"{color_map['ip']}IP: {ip}")
        print(f"{color_map['referral']}Riferito da: {ref_code}")
        if message:
            print(f"{color_map[status]}{message}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")

def load_list(filename):
    """Carica le righe da un file, ignorando le righe vuote."""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def save_wallet(ref_code, private_key, address):
    """Salva i dettagli del wallet in un file."""
    filename = f"klok_{ref_code}.txt"
    with open(filename, 'a') as f:
        f.write(f"{private_key}:{address}\n")

def generate_uuid():
    """Genera un UUID casuale."""
    return str(uuid.uuid4())

def get_current_time():
    """Ottieni l'orario UTC corrente in formato ISO."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def load_chat_messages():
    """Carica i messaggi di chat da chats.txt o usa i predefiniti."""
    try:
        with open('chats.txt', 'r') as f:
            lines = f.readlines()
        messages = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        return messages
    except FileNotFoundError:
        print(f"{Fore.RED}chats.txt non trovato, utilizzo messaggi predefiniti{Style.RESET_ALL}")
        return [
            "Qual è la tua opinione sulla tecnologia blockchain?",
            "Come vedi l'evoluzione dell'IA nel prossimo decennio?",
            "Cosa rende una startup di successo?",
            "Condividi un fatto scientifico interessante",
            "Qual è la tua innovazione tecnologica preferita?"
        ]

def generate_random_chat():
    """Seleziona un messaggio di chat casuale."""
    messages = load_chat_messages()
    return random.choice(messages)

def sign_message(private_key, address, nonce):
    """Firma il messaggio di autenticazione per Klokapp.ai."""
    try:
        current_time = get_current_time()
        message = f"""klokapp.ai wants you to sign in with your Ethereum account:
{address}


URI: https://klokapp.ai/
Version: 1
Chain ID: 1
Nonce: {nonce}
Issued At: {current_time}"""

        message_hash = encode_defunct(text=message)
        signed_message = w3.eth.account.sign_message(message_hash, private_key=private_key)
        return signed_message.signature.hex(), message
    except Exception as e:
        print(f"{Fore.RED}Errore nella firma del messaggio: {str(e)}{Style.RESET_ALL}")
        return None, None

def get_recaptcha_token():
    """Genera il token reCAPTCHA usando Puppeteer."""
    try:
        puppeteer_script = """
const puppeteer = require('puppeteer');

async function getRecaptchaToken(siteKey) {
    const browserivinchiapp.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    try {
        const page = await browser.newPage();
        await page.goto('https://klokapp.ai');

        await page.addScriptTag({
            url: `https://www.google.com/recaptcha/api.js?render=${siteKey}`
        });

        const token = await page.evaluate((siteKey) => {
            return new Promise((resolve, reject) => {
                grecaptcha.ready(() => {
                    grecaptcha.execute(siteKey, { action: 'verify' })
                        .then(token => resolve(token))
                        .catch(error => reject(error));
                });
            });
        }, siteKey);

        return token;
    } finally {
        await browser.close();
    }
}

getRecaptchaToken(process.argv[2])
    .then(token => console.log(token))
    .catch(error => {
        console.error('Error:', error);
        process.exit(1);
    });
        """

        with open('get_recaptcha.js', 'w') as f:
            f.write(puppeteer_script)

        result = subprocess.run(
            ['node', 'get_recaptcha.js', RECAPTCHA_SITE_KEY],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            raise Exception(f"Errore Puppeteer: {result.stderr}")

        token = result.stdout.strip()
        if not token:
            raise Exception("Token reCAPTCHA vuoto ricevuto")
        
        print(f"{Fore.GREEN}✅ Token reCAPTCHA generato: {token}{Style.RESET_ALL}")
        return token
    except Exception as e:
        print(f"{Fore.RED}❌ Errore token reCAPTCHA: {str(e)}{Style.RESET_ALL}")
        return None
    finally:
        try:
            os.remove('get_recaptcha.js')
        except:
            pass

def verify_recaptcha_token(token):
    """Verifica il token reCAPTCHA con l'API di Google (opzionale)."""
    if not RECAPTCHA_SECRET_KEY:
        print(f"{Fore.YELLOW}RECAPTCHA_SECRET_KEY non impostata, salto la verifica{Style.RESET_ALL}")
        return True  # Salta se la chiave segreta non è fornita
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': token
            }
        )
        result = response.json()
        if not result.get('success', False):
            raise Exception(f"Verifica reCAPTCHA fallita: {result}")
        print(f"{Fore.GREEN}✅ Token reCAPTCHA verificato con successo{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}❌ Errore verifica reCAPTCHA: {str(e)}{Style.RESET_ALL}")
        return False

def send_chat(session, chat_headers, chat_data):
    """Invia un messaggio di chat con logica di riprova."""
    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        try:
            response = session.post(
                'https://api1-pp.klokapp.ai/v1/chat',
                headers=chat_headers,
                json=chat_data,
                timeout=30
            )

            if response.status_code == 200:
                return response
            elif response.status_code == 500 and "rate_limit_exceeded" in response.text:
                print(f"{Fore.YELLOW}Limite di frequenza raggiunto, attesa di 30 secondi...{Style.RESET_ALL}")
                time.sleep(30)
            else:
                print(f"{Fore.RED}Fallito con codice di stato: {response.status_code}{Style.RESET_ALL}")
                if response.text:
                    print(f"{Fore.RED}Errore: {response.text}{Style.RESET_ALL}")

        except requests.exceptions.ReadTimeout:
            print(f"{Fore.YELLOW}Timeout della richiesta, riprovo...{Style.RESET_ALL}")
        except requests.exceptions.ChunkedEncodingError:
            print(f"{Fore.YELLOW}Connessione interrotta, riprovo...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Errore: {str(e)}{Style.RESET_ALL}")

        attempt += 1
        if attempt < max_attempts:
            time.sleep(2)

    return None

def perform_chats(session, headers):
    """Esegue chat casuali (3–5 per account)."""
    max_retries = 3
    retry_count = 0
    num_chats = random.randint(3, 5)
    successful_chats = 0
    chat_headers = get_chat_headers(headers.get('x-session-token', ''))

    while retry_count < max_retries and successful_chats < num_chats:
        try:
            for i in range(successful_chats, num_chats):
                chat_message = generate_random_chat()
                chat_id = generate_uuid()
                current_time = get_current_time()

                chat_data = {
                    "id": chat_id,
                    "title": "",
                    "messages": [
                        {
                            "role": "user",
                            "content": chat_message
                        }
                    ],
                    "sources": [],
                    "model": random.choice(MODELS),
                    "created_at": current_time,
                    "language": "english"
                }

                print(f"{Fore.CYAN}Creazione nuova chat con ID: {chat_id} usando modello: {chat_data['model']}{Style.RESET_ALL}")
                response = send_chat(session, chat_headers, chat_data)

                if response:
                    print(f"{Fore.GREEN}Chat {i+1}/{num_chats}: {chat_message}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Risposta ricevuta con successo{Style.RESET_ALL}")
                    successful_chats += 1

                    if i < num_chats - 1:
                        delay = random.uniform(5, 6)
                        print(f"{Fore.YELLOW}Attesa di {delay:.1f} secondi prima della prossima chat...{Style.RESET_ALL}")
                        time.sleep(delay)
                else:
                    raise Exception("Impossibile inviare la chat dopo molteplici tentativi")

            if successful_chats == num_chats:
                print(f"{Fore.GREEN}Completate con successo tutte le {num_chats} chat!{Style.RESET_ALL}")
                return True

        except Exception as e:
            retry_count += 1
            if retry_count < max_retries:
                print(f"{Fore.YELLOW}Sequenza di chat fallita a {successful_chats}/{num_chats}, riprovo...{Style.RESET_ALL}")
                time.sleep(2)
            else:
                print(f"{Fore.RED}Impossibile completare la sequenza di chat dopo {max_retries} tentativi. Completate {successful_chats}/{num_chats} chat.{Style.RESET_ALL}")
                return False

    return False

def get_headers():
    """Intestazioni predefinite per le richieste API."""
    return {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://klokapp.ai',
        'referer': 'https://klokapp.ai/',
        'authority': 'api1-pp.klokapp.ai',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Chromium";v="133", "Not(A:Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site'
    }

def get_chat_headers(session_token):
    """Intestazioni per le richieste API di chat."""
    return {
        'Host': 'api1-pp.klokapp.ai',
        'X-Session-Token': session_token,
        'Sec-Ch-Ua-Platform': random.choice(['"Windows"', '"macOS"', '"Linux"']),
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Ch-Ua': '"Chromium";v="133", "Not(A:Brand";v="99"',
        'User-Agent': random.choice(USER_AGENTS),
        'Sec-Ch-Ua-Mobile': '?0',
        'Accept': '*/*',
        'Origin': 'https://klokapp.ai',
        'Sec-Fetch-Site': 'same-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://klokapp.ai/',
        'Accept-Encoding': 'gzip, deflate, br',
        'Priority': 'u=1, i'
    }

def get_nonce(address):
    """Genera un nonce casuale per la firma."""
    try:
        url = 'https://api1-pp.klokapp.ai/v1/verify'
        headers = {
            'accept': '*/*',
            'access-control-request-method': 'POST',
            'access-control-request-headers': 'content-type',
            'origin': 'https://klokapp.ai',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'sec-fetch-dest': 'empty',
            'referer': 'https://klokapp.ai/',
            'accept-language': 'en-US,en;q=0.9'
        }

        print(f"{Fore.YELLOW}Invio richiesta OPTIONS a: {url}{Style.RESET_ALL}")
        response = requests.options(url, headers=headers)

        nonce = secrets.token_hex(48)
        print(f"{Fore.GREEN}Nonce generato: {nonce}{Style.RESET_ALL}")
        return nonce
    except Exception as e:
        print(f"{Fore.RED}Errore nella generazione del nonce: {str(e)}{Style.RESET_ALL}")
        return None

def login(address, signature, message, ref_code):
    """Accedi a Klokapp.ai con messaggio firmato e token reCAPTCHA."""
    try:
        session = requests.Session()
        print(f"{Fore.YELLOW}Generazione token reCAPTCHA...{Style.RESET_ALL}")
        recaptcha_token = get_recaptcha_token()
        if not recaptcha_token:
            raise Exception("Impossibile generare il token reCAPTCHA")

        # Opzionale: Verifica il token reCAPTCHA (decommenta se necessario)
        # if not verify_recaptcha_token(recaptcha_token):
        #     raise Exception("Verifica del token reCAPTCHA fallita")

        response = session.post(
            'https://api1-pp.klokapp.ai/v1/verify',
            headers=get_headers(),
            json={
                'signedMessage': signature,
                'message': message,
                'referral_code': ref_code,
                'recaptcha_token': recaptcha_token
            }
        )
        if response.status_code == 200:
            data = response.json()
            session_token = data.get('session_token', '')
            if not session_token:
                raise Exception("Nessun session_token nella risposta di verifica")
            session.headers.update(get_chat_headers(session_token))
            print(f"{Fore.GREEN}✅ Wallet connesso con successo!{Style.RESET_ALL}")
            return session
        print(f"{Fore.RED}Accesso fallito: {response.status_code} - {response.text}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}Errore durante l'accesso: {str(e)}{Style.RESET_ALL}")
        return None

def get_user_input():
    """Ottieni il numero di account da generare dall'utente."""
    while True:
        try:
            num_accounts = int(input(f"\n{Fore.YELLOW}Inserisci il numero di account da generare: {Style.RESET_ALL}"))
            if num_accounts > 0:
                return num_accounts
            print(f"{Fore.RED}Inserisci un numero positivo{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Inserisci un numero valido{Style.RESET_ALL}")

def create_wallet():
    """Genera un nuovo wallet Ethereum."""
    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    acct = Account.from_key(private_key)
    return private_key, acct.address

def main():
    """Logica principale dello script."""
    print_banner()

    refs = load_list('refs.txt')
    if not refs:
        print(f"{Fore.RED}Errore: Nessun codice di referral trovato in refs.txt{Style.RESET_ALL}")
        return

    successful_accounts = 0
    num_accounts = get_user_input()

    for i in range(num_accounts):
        wallet_count = i + 1
        ref_code = random.choice(refs)
        ip = "Connessione Diretta"
        log_message(wallet_count, "", ip, ref_code, "process")

        try:
            private_key, address = create_wallet()
            log_message(wallet_count, address, ip, ref_code, "info", "Wallet creato, ottenimento nonce...")

            nonce = get_nonce(address)
            if not nonce:
                log_message(wallet_count, address, ip, ref_code, "error", "Impossibile ottenere il nonce")
                continue

            signature, message = sign_message(private_key, address, nonce)
            if not signature:
                log_message(wallet_count, address, ip, ref_code, "error", "Impossibile firmare il messaggio")
                continue

            session = login(address, signature, message, ref_code)
            if not session:
                log_message(wallet_count, address, ip, ref_code, "error", "Accesso fallito")
                continue

            log_message(wallet_count, address, ip, ref_code, "success", "Accesso riuscito, avvio sequenza di chat...")

            if perform_chats(session, session.headers):
                save_wallet(ref_code, private_key, address)
                log_message(wallet_count, address, ip, ref_code, "success", "Tutte le chat completate con successo!")
                successful_accounts += 1
            else:
                log_message(wallet_count, address, ip, ref_code, "error", "Fallimento durante la sequenza di chat")

        except Exception as e:
            log_message(wallet_count, address, ip, ref_code, "error", f"Errore: {str(e)}")
            continue

        time.sleep(random.uniform(1, 2))

    print(f"\n{Fore.CYAN}Riepilogo:{Style.RESET_ALL}")
    print(f"Account creati: {successful_accounts}")

if __name__ == "__main__":
    main()
