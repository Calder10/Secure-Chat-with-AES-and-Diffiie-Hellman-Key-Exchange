import diffie_hellman as dh
import appscript

start_server_cmd="cd /Users/salvatorecalderaro/Google\ Drive/Università/Cybersecurity/Progetto/src  && python server.py"
start_client_cmd="cd /Users/salvatorecalderaro/Google\ Drive/Università/Cybersecurity/Progetto/src  && python client.py"



def run_client_server():
    appscript.app('Terminal').do_script(start_server_cmd)
    appscript.app('Terminal').do_script(start_client_cmd)


def main():
    dh.create_p_g()
    run_client_server()

if __name__=="__main__":
    main()