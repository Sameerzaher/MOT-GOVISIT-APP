# -*- coding: utf-8 -*-
import os, time, requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

OTP_API=os.getenv('OTP_API','http://localhost:8000'); ADMIN_TOKEN=os.getenv('ADMIN_TOKEN','change-me')
GOV_URL=os.getenv('GOV_URL','https://govisit.gov.il/he/authorities/authority/29')
HEADERS={'Authorization': f'Bearer {ADMIN_TOKEN}'}

def fetch_next_login():
    r=requests.get(f"{OTP_API}/api/login/next", headers=HEADERS, timeout=10); r.raise_for_status(); d=r.json()
    return d if d.get('id') else None

def wait_for_otp(phone, timeout=180):
    end=time.time()+timeout
    while time.time()<end:
        r=requests.get(f"{OTP_API}/api/otp/latest", params={'phone':phone}, headers=HEADERS, timeout=10)
        r.raise_for_status(); d=r.json()
        if d.get('code'): return d['code'], d['id']
        time.sleep(2)
    raise TimeoutError('OTP timeout')

def main():
    opts=Options(); opts.add_argument('--lang=he'); driver=webdriver.Chrome(options=opts); wait=WebDriverWait(driver,30)
    try:
        while True:
            job=fetch_next_login()
            if not job: time.sleep(2); continue
            jid, phone = job['id'], job['phone']
            driver.get(GOV_URL); time.sleep(2)
            # כאן תשלים את שלבי האתר שלך...
            # כשתשלח קוד SMS באתר:
            otp, otp_id = wait_for_otp(phone)
            # הזנת הקוד – דוגמה לשדה יחיד
            try:
                code_input = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, "input[autocomplete='one-time-code']")))
                code_input.clear(); code_input.send_keys(otp)
            except: pass
            print('[OK]', phone)
    finally:
        driver.quit()

if __name__=='__main__': main()
