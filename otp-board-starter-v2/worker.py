# -*- coding: utf-8 -*-
import os, time, json, contextlib, traceback, logging, requests, re
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException

# =================== Config ===================
OTP_API     = os.getenv("OTP_API", "https://mot-govisit-app.onrender.com")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "MyStrongAdminToken")
GOV_URL     = os.getenv("GOV_URL", "https://govisit.gov.il/he/app/appointment/29/1870/info")
HEADERS     = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

CHROME_BIN        = os.getenv("CHROME_BIN", "/usr/bin/chromium")
CHROMEDRIVER_PATH = os.getenv("CHROMEDRIVER_PATH", "/usr/bin/chromedriver")
HEADLESS_DEFAULT  = os.getenv("HEADLESS", "1").lower() in ("1", "true", "yes")

# Slots logging flags
SLOTS_SCAN      = os.getenv("SLOTS_SCAN", "1").lower() in ("1", "true", "yes")
SLOTS_DEEP      = os.getenv("SLOTS_DEEP", "0").lower() in ("1", "true", "yes")
SLOTS_MAX_DAYS  = int(os.getenv("SLOTS_MAX_DAYS", "10"))

# =================== Logging ===================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
LOGGER = logging.getLogger("worker")

@contextlib.contextmanager
def step(title: str):
    t0 = time.time()
    LOGGER.info(">> %s", title)
    try:
        yield
        LOGGER.info(">> %s (%.1fs)", title, time.time() - t0)
    except Exception:
        LOGGER.exception("FAIL %s (%.1fs)", title, time.time() - t0)
        raise

def dump_state(driver, tag: str):
    try:
        p = f"/tmp/worker_{int(time.time())}_{tag}.png"
        driver.save_screenshot(p)
        LOGGER.info("SNAP: %s", p)
    except Exception:
        pass
    with contextlib.suppress(Exception):
        LOGGER.info("URL: %s | TITLE: %s", driver.current_url, driver.title)

# =================== API helpers ===================
def http_get_json(url, params=None, timeout=15, retries=2):
    for i in range(retries + 1):
        try:
            r = requests.get(url, params=params, headers=HEADERS, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.ReadTimeout:
            if i == retries:
                raise
            time.sleep(0.8)
        except Exception:
            raise

def fetch_next_login():
    d = http_get_json(f"{OTP_API}/api/login/next", timeout=20, retries=1)
    return d if d and d.get("id") else None

def wait_for_otp(phone, timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        d = http_get_json(f"{OTP_API}/api/otp/latest", params={"phone": phone}, timeout=12, retries=0)
        if d and d.get("code"):
            return d["code"], d["id"]
        time.sleep(2.0)
    raise TimeoutException("OTP timeout")

def mark_used(otp_id):
    with contextlib.suppress(Exception):
        requests.post(f"{OTP_API}/api/otp/mark_used", params={"id": otp_id}, headers=HEADERS, timeout=10)

def mark_login(job_id, status):
    with contextlib.suppress(Exception):
        requests.post(f"{OTP_API}/api/login/mark", params={"id": job_id, "status": status}, headers=HEADERS, timeout=10)

# =================== Browser ===================
def build_driver(headless: bool):
    UA = os.getenv(
        "USER_AGENT",
        "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    )
    profile_dir = f"/tmp/chr-profile-{os.getpid()}-{int(time.time())}"
    os.makedirs(profile_dir, exist_ok=True)

    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    for flag in [
        "--no-sandbox","--disable-setuid-sandbox","--disable-dev-shm-usage",
        "--disable-gpu","--disable-extensions","--disable-software-rasterizer",
        "--no-zygote","--remote-allow-origins=*","--window-size=1280,900",
        "--lang=he-IL", f"--user-data-dir={profile_dir}",
        f"--disk-cache-dir={profile_dir}/cache","--remote-debugging-port=9222",
        "--disable-blink-features=AutomationControlled",
        f"--user-agent={UA}",
    ]:
        opts.add_argument(flag)
    opts.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.binary_location = CHROME_BIN
    opts.set_capability("goog:loggingPrefs", {"browser":"ALL","performance":"ALL"})

    service = Service(CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(60)

    # simple stealth
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        window.chrome = window.chrome || { runtime: {} };
        Object.defineProperty(navigator, 'plugins',   {get: () => [1,2,3,4]});
        Object.defineProperty(navigator, 'languages', {get: () => ['he-IL','he','en-US','en']});
    """})
    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setUserAgentOverride", {
        "userAgent": UA,
        "acceptLanguage": "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
        "platform": "Linux aarch64",
    })
    return driver

def is_radware_page(driver) -> bool:
    try:
        title = (driver.title or "").lower()
        url   = (driver.current_url or "").lower()
    except Exception:
        return False
    if "radware" in title or "verify" in title or "radware" in url or "verifying-your-browser" in url:
        return True
    with contextlib.suppress(Exception):
        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        if "incident id" in body_text or "verifying your browser" in body_text:
            return True
    return False

def wait_for_radware_to_clear(driver, timeout=90) -> bool:
    end = time.time() + timeout
    seen = False
    while time.time() < end:
        if is_radware_page(driver):
            seen = True
            time.sleep(2.5)
            continue
        return True
    if seen:
        LOGGER.warning("Radware still blocking after %.0fs", timeout)
    return False

def open_with_bypass(url: str, driver: webdriver.Chrome, headless: bool):
    with step(f"OPEN {url}"):
        driver.get(url)
    dump_state(driver, "after_open")
    if wait_for_radware_to_clear(driver, timeout=45):
        return driver, True
    if headless:
        LOGGER.warning("Radware blocked in headless. Relaunching visible browser...")
        with contextlib.suppress(Exception):
            driver.quit()
        driver = build_driver(headless=False)
        with step(f"OPEN (visible) {url}"):
            driver.get(url)
        dump_state(driver, "after_open_visible")
        if not wait_for_radware_to_clear(driver, timeout=90):
            dump_state(driver, "radware_stuck")
            return driver, False
        return driver, True
    dump_state(driver, "radware_stuck")
    return driver, False

# =================== Page actions ===================
def click_continue_from_info(wait: WebDriverWait) -> bool:
    selectors = [
        (By.ID, "continue_1870_29"),
        (By.XPATH, "//button[contains(normalize-space(.),'להמשך זימון')]"),
        (By.XPATH, "//a[contains(normalize-space(.),'להמשך זימון')]"),
    ]
    for how, sel in selectors:
        try:
            btn = wait.until(EC.element_to_be_clickable((how, sel)))
            try:
                btn.click()
            except Exception:
                wait._driver.execute_script("arguments[0].click();", btn)
            return True
        except Exception:
            continue
    return False

def switch_into_iframe_with_phone(driver, wait, timeout=30) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with contextlib.suppress(Exception):
            driver.switch_to.default_content()
            if driver.find_elements(By.CSS_SELECTOR, "input[type='tel'], input[name*='phone'], input[autocomplete='tel']"):
                return True
        with contextlib.suppress(Exception):
            frames = driver.find_elements(By.TAG_NAME, "iframe")
            for fr in frames:
                driver.switch_to.default_content()
                driver.switch_to.frame(fr)
                if driver.find_elements(By.CSS_SELECTOR, "input[type='tel'], input[name*='phone'], input[autocomplete='tel']"):
                    return True
            driver.switch_to.default_content()
        time.sleep(0.5)
    driver.switch_to.default_content()
    return False

def fill_phone_and_send_sms(wait: WebDriverWait, phone: str) -> bool:
    phone_input = wait.until(EC.visibility_of_element_located((
        By.CSS_SELECTOR, "input[type='tel'], input[name*='phone'], input[autocomplete='tel']"
    )))
    phone_input.clear()
    phone_input.send_keys(phone)

    xpaths = [
        "//*[contains(normalize-space(.),'שלח') and contains(normalize-space(.),'קוד')]",
        "//*[contains(normalize-space(.),'שלחו') and contains(normalize-space(.),'SMS')]",
        "//*[contains(normalize-space(.),'קבלת קוד')]",
        "//*[contains(normalize-space(.),'המשך') or contains(normalize-space(.),'כניסה')]",
        "//button[@type='submit']",
    ]
    for xp in xpaths:
        try:
            btn = wait.until(EC.element_to_be_clickable((By.XPATH, xp)))
            try:
                btn.click()
            except Exception:
                wait._driver.execute_script("arguments[0].click();", btn)
            return True
        except Exception:
            continue
    return False

# ===== OTP helpers =====
def find_otp_input(driver):
    sels = [
        "input[autocomplete='one-time-code']",
        "input[name*='code' i]",
        "input[id*='code' i]",
        "input[aria-label*='קוד']",
        "input[placeholder*='קוד']",
        "input[inputmode='numeric']",
        "input[type='tel']",
        "input[type='password']",
        "input[type='text']",
    ]
    for sel in sels:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
            els = [e for e in els if e.is_displayed() and e.is_enabled()]
            if els:
                return els[0]
        except Exception:
            pass
    return None

def enter_otp(wait: WebDriverWait, otp: str, timeout: int = 45) -> bool:
    """
    הזנת OTP – תומך בשדה יחיד או בקוביות (maxlength=1) ומדליק אירועי input/change.
    """
    d = wait._driver
    with contextlib.suppress(Exception):
        d.switch_to.default_content()

    end = time.time() + timeout
    while time.time() < end:
        el = find_otp_input(d)
        if el:
            try:
                d.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
            except Exception:
                pass
            with contextlib.suppress(Exception):
                el.clear()
            with contextlib.suppress(Exception):
                el.click()
            for ch in str(otp):
                el.send_keys(ch)
                time.sleep(0.02)
            with contextlib.suppress(Exception):
                d.execute_script(
                    "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                    "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));",
                    el
                )
            return True

        # נסיון לקוביות (תיבה לכל ספרה)
        try:
            boxes = d.find_elements(By.CSS_SELECTOR,
                "input[maxlength='1'], input[aria-label*='ספרה'], input[aria-label*='digit']")
            boxes = [b for b in boxes if b.is_displayed() and b.is_enabled()]
            if boxes and len(boxes) >= len(str(otp)):
                with contextlib.suppress(Exception):
                    d.execute_script("arguments[0].scrollIntoView({block:'center'});", boxes[0])
                for i, ch in enumerate(str(otp)):
                    with contextlib.suppress(Exception):
                        boxes[i].clear()
                    boxes[i].send_keys(ch)
                    time.sleep(0.02)
                return True
        except Exception:
            pass

        time.sleep(0.3)

    return False

def click_login_after_otp(wait: WebDriverWait) -> bool:
    """
    לוחץ על "התחברות" גם אם הכפתור מנוטרל: מסיר disabled/aria-disabled, מפעיל requestSubmit,
    נופל לפקודת ENTER משדה ה-OTP אם צריך.
    """
    driver = wait._driver
    labels_he = ["התחברות", "אישור", "כניסה", "המשך"]
    labels_en = ["Submit", "Continue", "Next", "Sign in", "Log in"]

    def try_click(el):
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass
        # לבטל נטרול
        with contextlib.suppress(Exception):
            driver.execute_script(
                "arguments[0].removeAttribute('disabled');"
                "arguments[0].setAttribute('aria-disabled','false');"
                "arguments[0].classList && arguments[0].classList.remove('disabled');",
                el
            )
        try:
            el.click()
            return True
        except Exception:
            with contextlib.suppress(Exception):
                driver.execute_script("arguments[0].click();", el)
                return True
        return False

    # 1) לפי טקסט בעברית/אנגלית
    for txt in labels_he + labels_en:
        try:
            btns = driver.find_elements(By.XPATH, f"//button[contains(normalize-space(.),'{txt}')]")
            btns += driver.find_elements(By.XPATH, f"//*[self::button or self::a][contains(normalize-space(.),'{txt}')]")
            for b in btns:
                if b.is_displayed():
                    if try_click(b):
                        return True
        except Exception:
            pass

    # 2) כל submit זמין
    try:
        for el in driver.find_elements(By.CSS_SELECTOR, "button[type='submit'], input[type='submit']"):
            if el.is_displayed():
                if try_click(el):
                    return True
    except Exception:
        pass

    # 3) בקשה ישירה ל-submit של הטופס
    try:
        ok = driver.execute_script("""
            const forms=[...document.querySelectorAll('form')];
            for(const f of forms){
                try{
                    const btn=f.querySelector('button,[type=submit]');
                    if(btn){ btn.removeAttribute('disabled'); btn.setAttribute('aria-disabled','false'); }
                    if(f.requestSubmit){ f.requestSubmit(btn||undefined); }
                    else { f.submit(); }
                    return true;
                }catch(e){}
            }
            return false;
        """)
        if ok:
            return True
    except Exception:
        pass

    # 4) אנטר מתוך שדה ה-OTP
    with contextlib.suppress(Exception):
        el = find_otp_input(driver)
        if el:
            el.send_keys(Keys.ENTER)
            return True

    return False

# ---- ID & Filters helpers ----
def find_id_input(driver):
    label_phrases = ["מספר זהות", "תעודת זהות", "ת.ז"]
    for phrase in label_phrases:
        for xp in [
            f"//label[contains(normalize-space(.),'{phrase}')]/following::input[1]",
            f"//div[.//label[contains(normalize-space(.),'{phrase}')]]//input",
        ]:
            try:
                el = driver.find_element(By.XPATH, xp)
                if el.is_displayed():
                    return el
            except Exception:
                pass
    for sel in ["input[name*='id']", "input[inputmode='numeric']",
                "input[aria-label*='זהות']", "input[placeholder*='זהות']"]:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, sel):
                if el.is_displayed():
                    return el
        except Exception:
            pass
    return None

def click_next_button(wait: WebDriverWait, timeout=15) -> bool:
    driver = wait._driver
    labels = ["השלב הבא", "הבא", "המשך", "Next", "Continue", "חפש תורים", "חיפוש", "חפש"]
    end = time.time() + timeout

    def try_request_submit() -> bool:
        try:
            return driver.execute_script("""
                const labels=arguments[0];
                function txt(el){return (el.innerText||el.textContent||'').trim();}
                const btns=[...document.querySelectorAll('button,[role=button],input[type=submit]')];
                for(const b of btns){const t=txt(b);
                  if(!labels.some(s=>t.includes(s))) continue;
                  const f=b.closest('form'); if(f){ b.disabled=false;
                      try{ if(f.requestSubmit) f.requestSubmit(b); else f.submit(); }catch(e){}
                      return true;
                  }
                } return false;
            """, labels) or False
        except Exception:
            return False

    while time.time() < end:
        xps = [f"//button[contains(normalize-space(.),'{t}')]" for t in labels] + ["//input[@type='submit']"]
        for xp in xps:
            try:
                for el in driver.find_elements(By.XPATH, xp):
                    try:
                        if not el.is_displayed(): continue
                        if el.get_attribute("disabled") or (el.get_attribute("aria-disabled") or "").lower() in ("true","1"):
                            continue
                        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
                        try:
                            el.click()
                        except Exception:
                            driver.execute_script("arguments[0].click();", el)
                        return True
                    except Exception:
                        continue
            except Exception:
                pass
        if try_request_submit():
            return True
        time.sleep(0.3)
    return False

def set_text(driver, el, value: str):
    el.click()
    el.send_keys(Keys.CONTROL, "a")
    el.send_keys(Keys.DELETE)
    for ch in value:
        el.send_keys(ch)
        time.sleep(0.02)
    with contextlib.suppress(Exception):
        driver.execute_script("arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                              "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));"
                              "arguments[0].blur && arguments[0].blur();", el)

def open_custom_select_and_choose(driver, box, wanted: str) -> bool:
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", box)
    except Exception:
        pass
    try:
        box.click()
    except Exception:
        driver.execute_script("arguments[0].click();", box)
    time.sleep(0.3)
    option_xps = [
        f"//*[@role='option' and contains(normalize-space(.),'{wanted}')]",
        f"//li[contains(normalize-space(.),'{wanted}')]",
        f"//div[contains(@class,'option') and contains(normalize-space(.),'{wanted}')]",
    ]
    for xp in option_xps:
        try:
            opt = WebDriverWait(driver, 5).until(EC.element_to_be_clickable((By.XPATH, xp)))
            try:
                opt.click()
            except Exception:
                driver.execute_script("arguments[0].click();", opt)
            return True
        except Exception:
            continue
    with contextlib.suppress(Exception):
        box.send_keys(wanted)
        time.sleep(0.2)
        box.send_keys(Keys.ENTER)
        return True
    return False

def set_select_like(driver, container, wanted: str) -> bool:
    if not wanted:
        return True
    tag = (container.tag_name or "").lower()
    if tag == "select":
        try:
            opts = container.find_elements(By.TAG_NAME, "option")
            for o in opts:
                if wanted in (o.text or ""):
                    o.click()
                    return True
        except Exception:
            pass
    return open_custom_select_and_choose(driver, container, wanted)

def find_labeled_field(driver, label_words, prefer_select=False):
    for word in label_words:
        for xp in [
            f"//label[contains(normalize-space(.),'{word}')]/following::*[(self::input or self::select or self::*[@role='combobox'])][1]",
            f"//div[.//label[contains(normalize-space(.),'{word}')]]//*[self::input or self::select or self::*[@role='combobox']]",
        ]:
            try:
                els = driver.find_elements(By.XPATH, xp)
                for el in els:
                    if el.is_displayed():
                        return el
            except Exception:
                pass
    if prefer_select:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, "[role='combobox'], select"):
                if el.is_displayed(): return el
        except Exception:
            pass
    try:
        for el in driver.find_elements(By.CSS_SELECTOR, "input"):
            if el.is_displayed(): return el
    except Exception:
        pass
    return None

def fill_id_and_next(wait: WebDriverWait, id_number: str) -> bool:
    if not id_number:
        LOGGER.info("No id_number in payload, skipping ID step")
        return True
    driver = wait._driver
    with contextlib.suppress(Exception):
        driver.switch_to.default_content()
    el = find_id_input(driver)
    if not el:
        LOGGER.info("ID input not found on current page, skipping ID step")
        return True
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
    except Exception:
        pass
    set_text(driver, el, str(id_number).strip())
    if click_next_button(wait, timeout=15):
        return True
    with contextlib.suppress(Exception):
        el.send_keys(Keys.ENTER)
        return True
    return False

def fill_filters_and_next(wait: WebDriverWait, payload: dict) -> bool:
    """
    ממלא עיר/סניף/תאריך/שעות אם מסופקים ב-payload:
      payload = { city, branch, date(YYYY-MM-DD), time_from(HH:MM), time_to(HH:MM) }
    ולוחץ 'חפש תורים' / 'השלב הבא'.
    """
    driver = wait._driver
    with contextlib.suppress(Exception):
        driver.switch_to.default_content()

    city   = (payload.get("city") or "").strip()
    branch = (payload.get("branch") or "").strip()
    date_v = (payload.get("date") or "").strip()
    t_from = (payload.get("time_from") or "").strip()
    t_to   = (payload.get("time_to") or "").strip()

    nothing_to_fill = not any([city, branch, date_v, t_from, t_to])
    if nothing_to_fill:
        LOGGER.info("No filters in payload; skipping filters step")
        return True

    filled_any = False

    # עיר
    if city:
        fld = find_labeled_field(driver, ["עיר", "יישוב"], prefer_select=True)
        if fld:
            try:
                if (fld.tag_name or "").lower() == "input":
                    set_text(driver, fld, city)
                else:
                    set_select_like(driver, fld, city)
                filled_any = True
            except Exception:
                pass

    # סניף / לשכה
    if branch:
        fld = find_labeled_field(driver, ["סניף", "לשכה"], prefer_select=True)
        if fld:
            try:
                if (fld.tag_name or "").lower() == "input":
                    set_text(driver, fld, branch)
                else:
                    set_select_like(driver, fld, branch)
                filled_any = True
            except Exception:
                pass

    # תאריך
    if date_v:
        fld = find_labeled_field(driver, ["תאריך"])
        if not fld:
            try:
                fld = driver.find_element(By.CSS_SELECTOR, "input[type='date']")
            except Exception:
                fld = None
        if fld:
            try:
                set_text(driver, fld, date_v)
                filled_any = True
            except Exception:
                pass

    # שעות
    if t_from:
        fld = find_labeled_field(driver, ["שעת התחלה", "משעה"])
        if not fld:
            try:
                fld = driver.find_element(By.CSS_SELECTOR, "input[type='time']")
            except Exception:
                fld = None
        if fld:
            try:
                set_text(driver, fld, t_from)
                filled_any = True
            except Exception:
                pass

    if t_to:
        fld = find_labeled_field(driver, ["שעת סיום", "עד שעה"])
        if fld:
            try:
                set_text(driver, fld, t_to)
                filled_any = True
            except Exception:
                pass

    # לחץ 'חפש תורים/המשך'
    if filled_any:
        if click_next_button(wait, timeout=15):
            return True
        # נסה ENTER על שדה אחרון שמילאנו
        with contextlib.suppress(Exception):
            (fld or driver.switch_to.active_element).send_keys(Keys.ENTER)
            return True

    return True  # לא קריטי אם לא מצאנו—נמשיך

# =================== Slots logging ===================
TIME_RE = re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d\b")

def _el_text(driver, el):
    try:
        t = (el.text or "").strip()
        if not t:
            t = (el.get_attribute("textContent") or "").strip()
        return t
    except Exception:
        return ""

def _current_date_label(driver):
    try:
        sel = driver.find_elements(
            By.XPATH,
            "//button[( @aria-pressed='true' or @aria-selected='true' or contains(@class,'selected') ) and string-length(normalize-space(.))<=2]"
        )
        if sel:
            a = sel[0].get_attribute("aria-label")
            if a:
                return a.strip()
    except Exception:
        pass
    try:
        headers = driver.find_elements(
            By.XPATH,
            "//*[self::h1 or self::h2 or self::h3 or self::div][contains(normalize-space(.),'תאריך') or contains(normalize-space(.),'יום') or contains(normalize-space(.),'חודש')]"
        )
        for h in headers:
            txt = _el_text(driver, h)
            if txt:
                return txt
    except Exception:
        pass
    return "תאריך לא מזוהה"

def _extract_times_on_page(driver):
    times = set()
    try:
        candidates = driver.find_elements(
            By.XPATH,
            "//*[self::button or self::li or self::div or self::span]"
            "[contains(normalize-space(.),':') and not(@aria-disabled='true') and not(@disabled)]"
        )
        for el in candidates:
            txt = _el_text(driver, el)
            if not txt:
                continue
            for m in TIME_RE.findall(txt):
                times.add(m)
    except Exception:
        pass
    return sorted(times)

def _click_safely(driver, el):
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
    except Exception:
        pass
    try:
        el.click()
    except Exception:
        driver.execute_script("arguments[0].click();", el)

def log_available_slots(wait: WebDriverWait, deep_scan: bool = False, max_days: int = 10):
    driver = wait._driver
    with contextlib.suppress(Exception):
        driver.switch_to.default_content()

    date_label = _current_date_label(driver)
    times_now = _extract_times_on_page(driver)
    if times_now:
        LOGGER.info("SLOTS | %s | %s", date_label, ", ".join(times_now))
    else:
        LOGGER.info("SLOTS | %s | אין שעות זמינות כרגע", date_label)

    if not deep_scan:
        return

    seen_days = set()
    scanned = 0
    for _ in range(max_days * 2):
        if scanned >= max_days:
            break
        try:
            day_buttons = driver.find_elements(
                By.XPATH,
                "//button[not(@disabled) and not(@aria-disabled='true') and normalize-space(.)!='' and string-length(normalize-space(.))<=2]"
            )
            target = None
            for db in day_buttons:
                label = db.get_attribute("aria-label") or _el_text(driver, db)
                label = (label or "").strip()
                if not label or label in seen_days:
                    continue
                target = db
                break

            if not target:
                break

            label = target.get_attribute("aria-label") or _el_text(driver, target)
            label = (label or "").strip()
            seen_days.add(label)

            _click_safely(driver, target)
            time.sleep(0.4)

            times = _extract_times_on_page(driver)
            if times:
                LOGGER.info("SLOTS | %s | %s", label or "?", ", ".join(times))
            else:
                LOGGER.info("SLOTS | %s | אין שעות", label or "?")
            scanned += 1
        except Exception:
            continue

# =================== Main loop ===================
def main():
    LOGGER.info("Starting worker | GOV_URL=%s | HEADLESS=%s", GOV_URL, HEADLESS_DEFAULT)
    driver = build_driver(headless=HEADLESS_DEFAULT)
    wait = WebDriverWait(driver, 30)

    try:
        while True:
            with step("FETCH JOB"):
                job = fetch_next_login()
            if not job:
                time.sleep(1.0)
                continue

            jid      = job["id"]
            phone    = job["phone"]
            payload  = job.get("payload") or {}
            id_num   = (payload.get("id_number") or "").strip()
            LOGGER.info("Job #%s for phone %s", jid, phone)

            try:
                driver, ok = open_with_bypass(GOV_URL, driver, headless=HEADLESS_DEFAULT)
                if not ok:
                    raise RuntimeError("radware_blocked")

                with step("CLICK continue button"):
                    if not click_continue_from_info(wait):
                        dump_state(driver, "no_continue_button")
                        raise RuntimeError("continue button not found")

                time.sleep(1.0)

                with step("FIND phone field (iframe aware)"):
                    if not switch_into_iframe_with_phone(driver, wait, timeout=40):
                        dump_state(driver, "no_phone_iframe")
                        raise RuntimeError("phone field not found")

                with step("SEND SMS"):
                    if not fill_phone_and_send_sms(wait, phone):
                        dump_state(driver, "no_sms_button")
                        raise RuntimeError("could not trigger sms")

                with step("WAIT OTP"):
                    otp, otp_id = wait_for_otp(phone)
                    LOGGER.info("OTP: %s", otp)

                with step("ENTER OTP"):
                    if not enter_otp(wait, otp):
                        dump_state(driver, "no_otp_fields")
                        raise RuntimeError("otp fields not found")

                with step("CLICK login after OTP"):
                    clicked = click_login_after_otp(wait)
                    time.sleep(0.5)
                    # המתן לניווט מתוך מסך האימות
                    with contextlib.suppress(Exception):
                        WebDriverWait(driver, 10).until(lambda d: "auth/verify" not in (d.current_url or ""))

                mark_used(otp_id)
                mark_login(jid, "done")

                with contextlib.suppress(Exception):
                    driver.switch_to.default_content()

                with step("FILL ID and NEXT"):
                    fill_id_and_next(wait, id_num)

                with step("FILL filters (city/branch/date/time) and NEXT"):
                    fill_filters_and_next(wait, payload)

                if SLOTS_SCAN:
                    with step("LIST available slots"):
                        log_available_slots(wait, deep_scan=SLOTS_DEEP, max_days=SLOTS_MAX_DAYS)

                dump_state(driver, "done")
                LOGGER.info("[OK] %s", phone)

            except Exception as e:
                LOGGER.error("[FAIL] %s: %s", phone, e)
                traceback.print_exc()
                mark_login(jid, "failed")
                with contextlib.suppress(Exception):
                    driver.switch_to.default_content()

    finally:
        with contextlib.suppress(Exception):
            driver.quit()

if __name__ == "__main__":
    main()
