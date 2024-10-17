#!/bin/bash

resultfile="Results_$(date '+%F_%H:%M:%S').txt"
postdb="TextData.json"
statis="ChartData.json"
action="Solutions.json"


U_01() {
	echo ""  >> $resultfile 2>&1
	echo "[ " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1
	echo "[ " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-01(상) | 1. 계정관리 > 1.1 root 계정 원격접속 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"01\", " >> $postdb 2>&1
	echo "  \"id\" : \"01\", " >> $action 2>&1
	echo " 양호 판단 기준 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우" >> $resultfile 2>&1
	echo "  \"조치방법\" : \"원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		# /etc/services 파일 내 telnet 서비스의 포트 번호가 설정되어 있는지 확인하고, 설정되어 있다면 실행 중인지 확인함
		telnet_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $telnet_port_count -gt 0 ]; then
			telnet_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#telnet_port[@]}; i++))
			do
				netstat_telnet_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${telnet_port[$i]}" | wc -l`
				if [ $netstat_telnet_count -gt 0 ]; then
					if [ -f /etc/pam.d/login ]; then
						pam_securetty_so_count=`grep -vE '^#|^\s#' /etc/pam.d/login | grep -i 'pam_securetty.so' | wc -l`
						if [ $pam_securetty_so_count -gt 0 ]; then
							if [ -f /etc/securetty ]; then
								etc_securetty_pts_count=`grep -vE '^#|^\s#' /etc/securetty | grep '^ *pts' | wc -l`
								if [ $etc_securetty_pts_count -gt 0 ]; then
									echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " telnet 서비스를 사용하고, /etc/securetty 파일에 pts 부분이 제거 또는 주석 처리되어 있지 않습니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/securetty 파일에 pts 부분이 제거 또는 주석 처리되어 있지 않습니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " telnet 서비스를 사용하고, /etc/securetty 파일이 없습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/securetty 파일이 없습니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " telnet 서비스를 사용하고, /etc/pam.d/login 파일에 pam_securetty.so 모듈이 제거 또는 주석 처리되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/pam.d/login 파일에 pam_securetty.so 모듈이 제거 또는 주석 처리되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " telnet 서비스를 사용하고, /etc/pam.d/login 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/pam.d/login 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	# 위 과정에서 확인되지 않을 경우를 대비하여 ps 명령으로 telnet 서비스가 실행 중인지 확인함
	ps_telnet_count=`ps -ef | grep -i 'telnet' | grep -v 'grep' | wc -l`
	if [ $ps_telnet_count -gt 0 ]; then
		if [ -f /etc/pam.d/login ]; then
			pam_securetty_so_count=`grep -vE '^#|^\s#' /etc/pam.d/login | grep -i 'pam_securetty.so' | wc -l`
			if [ $pam_securetty_so_count -gt 0 ]; then
				if [ -f /etc/securetty ]; then
					etc_securetty_pts_count=`grep -vE '^#|^\s#' /etc/securetty | grep '^ *pts' | wc -l`
					if [ $etc_securetty_pts_count -gt 0 ]; then
						echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " telnet 서비스를 사용하고, /etc/securetty 파일에 pts 부분이 제거 또는 주석 처리되어 있지 않습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/securetty 파일에 pts 부분이 제거 또는 주석 처리되어 있지 않습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " telnet 서비스를 사용하고, /etc/securetty 파일이 없습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/securetty 파일이 없습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " telnet 서비스를 사용하고, /etc/pam.d/login 파일에 pam_securetty.so 모듈이 제거 또는 주석 처리되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/pam.d/login 파일에 pam_securetty.so 모듈이 제거 또는 주석 처리되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " telnet 서비스를 사용하고, /etc/pam.d/login 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/pam.d/login 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		
		fi
	fi
	# sshd_config 파일의 존재 여부를 검색하고, 존재한다면 ssh 서비스가 실행 중일 때 점검할 별도의 배열에 저장함
	sshd_config_count=`find / -name 'sshd_config' -type f 2> /dev/null | wc -l`
	if [ $sshd_config_count -gt 0 ]; then
		sshd_config_file=(`find / -name 'sshd_config' -type f 2> /dev/null`)
	fi
	# /etc/services 파일 내 ssh 서비스의 포트 번호가 설정되어 있는지 확인하고, 설정되어 있다면 실행 중인지 확인함
	if [ -f /etc/services ]; then
		ssh_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ssh" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $ssh_port_count -gt 0 ]; then
			ssh_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ssh" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#ssh_port[@]}; i++))
			do
				netstat_sshd_enable_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ssh_port[$i]}" | wc -l`
				if [ $netstat_sshd_enable_count -gt 0 ]; then
					if [ ${#sshd_config_file[@]} -eq 0 ]; then
						echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ssh 서비스를 사용하고, sshd_config 파일이 없습니다." >> $resultfile 2>&1
						echo "   \"결과상세\" : \"ssh 서비스를 사용하고, sshd_config 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
					for ((j=0; j<${#sshd_config_file[@]}; j++))
					do
						sshd_permitrootlogin_no_count=`grep -vE '^#|^\s#' ${sshd_config_file[$j]} | grep -i 'permitrootlogin' | grep -i 'no' | wc -l`
						if [ $sshd_permitrootlogin_no_count -eq 0 ]; then
							echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			done
		fi
	fi
	# 위 과정에서 확인되지 않을 경우를 대비하여 sshd_config 파일 내 ssh 서비스의 포트 번호가 설정되어 있는지 확인하고, 설정되어 있다면 실행 중인지 확인함
	if [ ${#sshd_config_file[@]} -gt 0 ]; then
		for ((i=0; i<${#sshd_config_file[@]}; i++))
		do
			ssh_port_count=`grep -vE '^#|^\s#' ${sshd_config_file[$i]} | grep -i 'port'  | awk '{print $2}' | wc -l`
			if [ $ssh_port_count -gt 0 ]; then
				ssh_port=(`grep -vE '^#|^\s#' ${sshd_config_file[$i]} | grep -i 'port'  | awk '{print $2}'`)
				for ((j=0; j<${#ssh_port[@]}; j++))
				do
					netstat_sshd_enable_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ssh_port[$j]}" | wc -l`
					if [ $netstat_sshd_enable_count -gt 0 ]; then
						for ((k=0; k<${#sshd_config_file[@]}; k++))
						do
							sshd_permitrootlogin_no_count=`grep -vE '^#|^\s#' ${sshd_config_file[$k]} | grep -i 'permitrootlogin' | grep -i 'no' | wc -l`
							if [ $sshd_permitrootlogin_no_count -eq 0 ]; then
								echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					fi
				done
			fi
		done
	fi
	# 위 과정에서 확인되지 않을 경우를 대비하여 ps 명령으로 ssh 서비스가 실행 중인지 확인함
	ps_sshd_enable_count=`ps -ef | grep -i 'sshd' | grep -v 'grep' | wc -l`
	if [ $ps_sshd_enable_count -gt 0 ]; then
		if [ ${#sshd_config_file[@]} -eq 0 ]; then
			echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " ssh 서비스를 사용하고, sshd_config 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"ssh 서비스를 사용하고, sshd_config 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
		for ((i=0; i<${#sshd_config_file[@]}; i++))
		do
			sshd_permitrootlogin_no_count=`grep -vE '^#|^\s#' ${sshd_config_file[$i]} | grep -i 'permitrootlogin' | grep -i 'no' | wc -l`
			if [ $sshd_permitrootlogin_no_count -eq 0 ]; then
				echo " > U-01 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"ssh 서비스를 사용하고, sshd_config 파일에서 root 계정의 원격 접속이 허용되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	fi
	echo " > U-01 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우\" " >> $postdb 2>&1
	return 0
}



U_02() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-02(상) | 1. 계정관리 > 1.2 패스워드 복잡성 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"02\", " >> $postdb 2>&1
	echo "  \"id\" : \"02\", " >> $action 2>&1
	echo " 양호 판단 기준 : 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 계정과 유사하지 않은 8자 이상의 영문, 숫자, 특수문자의 조합으로 암호 설정 및 패스워드 복잡성 옵션 설정" >> $resultfile 2>&1
	echo "  \"조치방법\" : \"계정과 유사하지 않은 8자 이상의 영문, 숫자, 특수문자의 조합으로 암호 설정 및 패스워드 복잡성 옵션 설정\" " >> $action 2>&1
	file_exists_count=0 # 패스워드 설정 파일 존재 시 카운트할 변수
	minlen_file_exists_count=0 # 패스워드 최소 길이 설정 파일 존재 시 카운트할 변수
	no_settings_in_minlen_file=0 # 설정 파일 존재하는데, 최소 길이에 대한 설정이 없을 때 카운트할 변수 -> 추후 file_exists_count 변수와 값을 비교하여 동일하면 모든 파일에 패스워드 최소 길이 설정이 없는 것이므로 취약으로 판단함
	mininput_file_exists_count=0 # 패스워드 최소 입력 설정 파일 존재 시 카운트할 변수
	no_settings_in_mininput_file=0 # 설정 파일 존재하는데, 최소 입력에 대한 설정이 없을 때 카운트할 변수 -> 추후 mininput_file_exists_count 변수와 값을 비교하여 동일하면 모든 파일에 패스워드 최소 입력 설정이 없는 것이므로 취약으로 판단함
	input_options=("lcredit" "ucredit" "dcredit" "ocredit")
	input_modules=("pam_pwquality.so" "pam_cracklib.so" "pam_unix.so")
	# /etc/login.defs 파일 내 패스워드 최소 길이 설정 확인함
	if [ -f /etc/login.defs ]; then
		((file_exists_count++))
		((minlen_file_exists_count++))
		etc_logindefs_minlen_count=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_LEN' | awk '{print $2}' | wc -l`
		if [ $etc_logindefs_minlen_count -gt 0 ]; then
		etc_logindefs_minlen_value=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_LEN' | awk '{print $2}'`
			if [ $etc_logindefs_minlen_value -lt 8 ]; then
				echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/login.defs 파일에 최소 길이(PASS_MIN_LEN)가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/login.defs 파일에 최소 길이(PASS_MIN_LEN)가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			((no_settings_in_minlen_file++))
		fi
	fi
	# /etc/pam.d/system-auth 파일 내 패스워드 최소 길이와 최소 입력 확인함
	if [ -f /etc/pam.d/system-auth ]; then
		((file_exists_count++))
		# 패스워드 최소 길이 체크
		for ((i=0; i<${#input_modules[@]}; i++))
		do
			((minlen_file_exists_count++))
			etc_pamd_systemauth_minlen_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'minlen' | grep -i ${input_modules[$i]} | wc -l`
			if [ $etc_pamd_systemauth_minlen_count -gt 0 ]; then
				etc_pamd_systemauth_minlen_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'minlen' | grep -i ${input_modules[$i]} | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,2,1)}'`
				if [ $etc_pamd_systemauth_minlen_value -lt 8 ]; then
					etc_pamd_systemauth_minlen_second_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'minlen' | grep -i ${input_modules[$i]} | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,3,1)}'`
					if [[ $etc_pamd_systemauth_minlen_second_value != [0-9] ]]; then
						echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/pam.d/system-auth 파일에 최소 길이(minlen)가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/pam.d/system-auth 파일에 최소 길이(minlen)가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			else
				((no_settings_in_minlen_file++))
			fi
		done
		# 패스워드 최소 입력 체크
		for ((i=0; i<${#input_modules[@]}; i++))
		do
			for ((j=0; j<${#input_options[@]}; j++))
			do
				((mininput_file_exists_count++))
				etc_pamd_systemauth_mininput_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${input_options[$j]} | grep -i ${input_modules[$i]} | wc -l`
				if [ $etc_pamd_systemauth_mininput_count -gt 0 ]; then
					etc_pamd_systemauth_mininput_dash=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${input_options[$j]} | grep -i ${input_modules[$i]} | awk -F ${input_options[$j]} '{gsub(" ", "", $0); print substr($2,2,1)}'`
					if [ $etc_pamd_systemauth_mininput_dash == - ]; then
						etc_pamd_systemauth_mininput_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${input_options[$j]} | grep -i ${input_modules[$i]} | awk -F ${input_options[$j]} '{gsub(" ", "", $0); print substr($2,3,1)}'`
						if [ $etc_pamd_systemauth_mininput_value -lt 1 ]; then
							echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/pam.d/system-auth 파일에 영문, 숫자, 특수문자의 최소 입력이 1 미만으로 설정되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/pam.d/system-auth 파일에 영문, 숫자, 특수문자의 최소 입력이 1 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/pam.d/system-auth 파일에 영문, 숫자, 특수문자의 최소 입력에 대한 설정이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/pam.d/system-auth 파일에 영문, 숫자, 특수문자의 최소 입력에 대한 설정이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					((no_settings_in_mininput_file++))
				fi
			done
		done
	fi
	# /etc/security/pwquality.conf 파일 내 패스워드 최소 길이와 최소 입력 확인함
	if [ -f /etc/security/pwquality.conf ]; then
		((file_exists_count++))
		# 패스워드 최소 길이 체크
		((minlen_file_exists_count++))
		etc_security_pwqualityconf_minlen_count=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | wc -l`
		if [ $etc_security_pwqualityconf_minlen_count -gt 0 ]; then
			etc_security_pwqualityconf_minlen_value=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,2,1)}'`
			if [ $etc_security_pwqualityconf_minlen_value -lt 8 ]; then
				etc_security_pwqualityconf_minlen_second_value=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,3,1)}'`
				if [[ $etc_security_pwqualityconf_minlen_second_value != [0-9] ]]; then
					echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/security/pwquality.conf 파일에 최소 길이(minlen)가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 최소 길이(minlen)가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				if [ -f /etc/pam.d/system-auth ]; then
					etc_pamd_systemauth_module_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'pam_pwquality.so' | wc -l`
					if [ $etc_pamd_systemauth_module_count -eq 0 ]; then
						echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >>   $resultfile 2>&1
					echo "  \"결과상세\" : \" /etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1 
					return 0
				fi
			fi
		else
			((no_settings_in_minlen_file++))
		fi
		# 패스워드 최소 입력 체크
		for ((i=0; i<${#input_options[@]}; i++))
		do
			((mininput_file_exists_count++))
			etc_security_pwqualityconf_mininput_count=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i ${input_options[$i]} | wc -l`
			if [ $etc_security_pwqualityconf_mininput_count -gt 0 ]; then
				etc_security_pwqualityconf_mininput_dash=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i ${input_options[$i]} | awk -F ${input_options[$i]} '{gsub(" ", "", $0); print substr($2,2,1)}'`
				if [[ $etc_security_pwqualityconf_mininput_dash =~ - ]]; then
					etc_security_pwqualityconf_mininput_value=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i ${input_options[$i]} | awk -F ${input_options[$i]} '{gsub(" ", "", $0); print substr($2,3,1)}'`
					if [ $etc_security_pwqualityconf_mininput_value -ge 1 ]; then
						if [ -f /etc/pam.d/system-auth ]; then
							etc_pamd_systemauth_module_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'pam_pwquality.so' | wc -l`
							if [ $etc_pamd_systemauth_module_count -eq 0 ]; then
								echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " /etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력을 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력을 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력을 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력을 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력이 1 미만으로 설정되어 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력이 1 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력에 대한 설정이 없습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 영문, 숫자, 특수문자의 최소 입력에 대한 설정이 없습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				((no_settings_in_mininput_file++))
			fi
		done
	fi
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 패스워드의 복잡성을 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"패스워드의 복잡성을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	elif [ $minlen_file_exists_count -eq $no_settings_in_minlen_file ]; then
		echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 패스워드의 최소 길이를 설정한 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"패스워드의 최소 길이를 설정한 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	elif [ $mininput_file_exists_count -eq $no_settings_in_mininput_file ]; then
		echo " > U-02 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 패스워드의 영문, 숫자, 특수문자의 최소 입력을 설정한 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"패스워드의 영문, 숫자, 특수문자의 최소 입력을 설정한 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
	echo " > U-02 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우\" " >> $postdb 2>&1
	return 0
}



U_03() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-03(상) | 1. 계정관리 > 1.3 계정 잠금 임계값 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"03\", " >> $postdb 2>&1
	echo "  \"id\" : \"03\", " >> $action 2>&1
	echo " 양호 판단 기준 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우 "  >> $resultfile 2>&1
	echo "     조치방법 : 계정 잠금 임계값을 10회 이하로 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"계정 잠금 임계값을 10회 이하로 설정 \" " >> $action 2>&1 
	deny_modules=("pam_tally2.so" "pam_faillock.so")
	# /etc/pam.d/system-auth 파일 내 계정 잠금 임계값 설정 확인함
	if [ -f /etc/pam.d/system-auth ]; then
		for ((i=0; i<${#deny_modules[@]}; i++))
		do
			etc_pamd_systemauth_deny_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${deny_modules[$i]} | grep -i 'deny' | wc -l`
			if [ $etc_pamd_systemauth_deny_count -gt 0 ]; then
				etc_pamd_systemauth_deny_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${deny_modules[$i]} | grep -i 'deny' | awk -F 'deny' '{gsub(" ", "", $0); print substr($2,2,1)}'`
				etc_pamd_systemauth_deny_second_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${deny_modules[$i]} | grep -i 'deny' | awk -F 'deny' '{gsub(" ", "", $0); print substr($2,3,1)}'`
				etc_pamd_systemauth_deny_third_value=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i ${deny_modules[$i]} | grep -i 'deny' | awk -F 'deny' '{gsub(" ", "", $0); print substr($2,4,1)}'`
				if [ $etc_pamd_systemauth_deny_value -eq 0 ]; then
					continue
				elif [ $etc_pamd_systemauth_deny_value -eq 1 ]; then
					if [[ $etc_pamd_systemauth_deny_second_value =~ [1-9] ]]; then
						echo " > U-03 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo " /etc/pam.d/system-auth 파일에 계정 잠금 임계값이 11회 이상으로 설정되어 있습니다." >> $resultfile 2>&1
						return 0
					else
						if [[ $etc_pamd_systemauth_deny_third_value =~ [0-9] ]]; then
							echo " > U-03 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo " /etc/pam.d/system-auth 파일에 계정 잠금 임계값이 11회 이상으로 설정되어 있습니다." >> $resultfile 2>&1
							return 0
						fi
					fi
				else
					if [[ $etc_pamd_systemauth_deny_second_value =~ [0-9] ]]; then
						echo " > U-03 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo " /etc/pam.d/system-auth 파일에 계정 잠금 임계값이 11회 이상으로 설정되어 있습니다." >> $resultfile 2>&1
						return 0
					fi
				fi
			else
				echo " > U-03 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " 계정 잠금 임계값을 설정한 파일이 없습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"계정 잠금 임계값을 설정한 파일이 없습니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	else
		echo " > U-03 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 계정 잠금 임계값을 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"계정 잠금 임계값을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
	echo " > U-03 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우\" " >> $postdb 2>&1
	return 0
}


U_04() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-04(상) | 1. 계정관리 > 1.4 패스워드 파일 보호 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"04\", " >> $postdb 2>&1
	echo "  \"id\" : \"04\", " >> $action 2>&1
	echo " 양호 판단 기준 : 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 패스워드 암호화 저장∙관리 설정 적용" >> $resultfile 2>&1
	echo "  \"조치방법\" : \"패스워드 암호화 저장∙관리 설정 적용\" " >> $action 2>&1
	if [ `awk -F : '$2!="x"' /etc/passwd | wc -l` -gt 0 ]; then
		echo " > U-04 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 쉐도우 패스워드를 사용하고 있지 않습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"쉐도우 패스워드를 사용하고 있지 않습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-04 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우\" " >> $postdb 2>&1
		return 0
	fi
		
}


U_05() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-05(상) | 2. 파일 및 디렉토리 관리 > 2.1 root홈, 패스 디렉터리 권한 및 패스 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"05\", " >> $postdb 2>&1
	echo "  \"id\" : \"05\", " >> $action 2>&1
	echo " 양호 판단 기준 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"  >> $resultfile 2>&1
	echo "     조치방법 : root 계정의 환경변수 설정파일(“/.profile”, “/.cshrc” 등)과 “/etc/profile” 등에서 PATH 환경변수에 포함되어 있는 현재 디렉터리를 나타내는 “.”을 PATH 환경변수의 마지막으로 이동 " >> $resultfile 2>&1
	echo " 		* “/etc/profile”, root 계정의 환경변수 파일, 일반계정의 환경변수 파일을 순차적으로 검색하여 확인"  >> $resultfile 2>&1
	echo "  \"조치방법\" : \"root 계정의 환경변수 설정파일(“/.profile”, “/.cshrc” 등)과 “/etc/profile” 등에서 PATH 환경변수에 포함되어 있는 현재 디렉터리를 나타내는 “.”을 PATH 환경변수의 마지막으로 이동. /etc/profile”, root 계정의 환경변수 파일, 일반계정의 환경변수 파일 순서로 확인 \" " >> $action 2>&1
	if [ `echo $PATH | grep -E '\.:|::' | wc -l` -gt 0 ]; then
		echo " > U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		# /etc 디렉터리 내 설정 파일의 PATH 변수 중 누락이 있을 가능성을 생각하여 추가 확인함
		path_settings_files=("/etc/profile" "/etc/.login" "/etc/csh.cshrc" "/etc/csh.login" "/etc/environment")
		for ((i=0; i<${#path_settings_files[@]}; i++))
		do
			if [ -f ${path_settings_files[$i]} ]; then
				path_settings_file_path_variable_exists_count=`grep -vE '^#|^\s#' ${path_settings_files[$i]} | grep 'PATH=' | wc -l`
				if [ $path_settings_file_path_variable_exists_count -gt 0 ]; then
					path_settings_file_path_variable_value_count=`grep -vE '^#|^\s#' ${path_settings_files[$i]} | grep 'PATH=' | grep -E '\.:|::' | wc -l`
					if [ $path_settings_file_path_variable_value_count -gt 0 ]; then
						echo " > U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc 디렉터리 내 Start Profile에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc 디렉터리 내 Start Profile에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			fi
		done
		# 사용자 홈 디렉터리 내 설정 파일의 PATH 변수 중 누락이 있을 가능성을 생각하여 추가 확인함
		path_settings_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
		user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
		user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
		for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
		do
			user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
		done
		user_homedirectory_path[${#user_homedirectory_path[@]}]=/root
		for ((i=0; i<${#user_homedirectory_path[@]}; i++))
		do
			for ((j=0; j<${#path_settings_files[@]}; j++))
			do
				if [ -f ${user_homedirectory_path[$i]}/${path_settings_files[$j]} ]; then
					path_settings_file_path_variable_exists_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${path_settings_files[$j]} | grep 'PATH=' | wc -l`
					if [ $path_settings_file_path_variable_exists_count -gt 0 ]; then
						path_settings_file_path_variable_value_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${path_settings_files[$j]} | grep 'PATH=' | grep -E '\.:|::' | wc -l`
						if [ $path_settings_file_path_variable_value_count -gt 0 ]; then
							echo " > U-05 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${user_homedirectory_path[$i]} 디렉터리 내 ${path_settings_files[$j]} 파일에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${user_homedirectory_path[$i]} 디렉터리 내 ${path_settings_files[$j]} 파일에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				fi
			done
		done
	fi
	echo " > U-05 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우\" " >> $postdb 2>&1
	return 0
}



U_06() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-06(상) | 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"06\", " >> $postdb 2>&1
	echo "  \"id\" : \"06\", " >> $action 2>&1
	echo " 양호 판단 기준 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 소유자가 존재하지 않는 파일 및 디렉터리 삭제 또는, 소유자 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"소유자가 존재하지 않는 파일 및 디렉터리 삭제 또는, 소유자 변경\" " >> $action 2>&1
	if [ `find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l` -gt 0 ]; then
		echo " > U-06 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-06 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_07() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-07(상) | 2. 파일 및 디렉토리 관리 > 2.3 /etc/passwd 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"07\", " >> $postdb 2>&1
	echo "  \"id\" : \"07\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/passwd” 파일의 소유자 및 권한 변경 (소유자 root, 권한 644) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/passwd” 파일의 소유자 및 권한 변경 (소유자 root, 권한 644)\" " >> $action 2>&1
	if [ -f /etc/passwd ]; then		
		etc_passwd_owner_name=`ls -l /etc/passwd | awk '{print $3}'`
		if [[ $etc_passwd_owner_name =~ root ]]; then
			etc_passwd_permission=`stat /etc/passwd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_passwd_permission -le 644 ]; then
				etc_passwd_owner_permission=`stat /etc/passwd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_passwd_owner_permission -eq 0 ] || [ $etc_passwd_owner_permission -eq 2 ] || [ $etc_passwd_owner_permission -eq 4 ] || [ $etc_passwd_owner_permission -eq 6 ]; then
					etc_passwd_group_permission=`stat /etc/passwd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_passwd_group_permission -eq 0 ] || [ $etc_passwd_group_permission -eq 4 ]; then
						etc_passwd_other_permission=`stat /etc/passwd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_passwd_other_permission -eq 0 ] || [ $etc_passwd_other_permission -eq 4 ]; then
							echo " > U-07 결과 : 양호(Good)" >> $resultfile 2>&1
							echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
							echo "  \"결과상세\" : \"/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-07 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/passwd 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"etc/passwd 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-07 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/passwd 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/passwd 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-07 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/passwd 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/passwd 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-07 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/passwd 파일의 권한이 644보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/passwd 파일의 권한이 644보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-07 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/passwd 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/passwd 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-07 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/passwd 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/passwd 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_08() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-08(상) | 2. 파일 및 디렉토리 관리 > 2.4 /etc/shadow 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"08\", " >> $postdb 2>&1
	echo "  \"id\" : \"08\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/shadow” 파일의 소유자 및 권한 변경 (소유자 root, 권한 400) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/shadow” 파일의 소유자 및 권한 변경 (소유자 root, 권한 400)\" " >> $action 2>&1
	if [ -f /etc/shadow ]; then
		etc_shadow_owner_name=`ls -l /etc/shadow | awk '{print $3}'`
		if [[ $etc_shadow_owner_name =~ root ]]; then
			etc_shadow_permission=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_shadow_permission -le 400 ]; then
				etc_shadow_owner_permission=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_shadow_owner_permission -eq 0 ] || [ $etc_shadow_owner_permission -eq 4 ]; then
					etc_shadow_group_permission=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_shadow_group_permission -eq 0 ]; then
						etc_shadow_other_permission=`stat /etc/shadow | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_shadow_other_permission -eq 0 ]; then
							echo " > U-08 결과 : 양호(Good)" >> $resultfile 2>&1
							echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
							echo "  \"결과상세\" : \"/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-08 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/shadow 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/shadow 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-08 결과 : N/A" >> $resultfile 2>&1
						echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
						echo " /etc/shadow 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/shadow 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-08 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/shadow 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/shadow 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-08 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/shadow 파일의 권한이 400보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/shadow 파일의 권한이 400보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-08 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/shadow 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/shadow 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-08 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/shadow 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/shadow 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_09() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-09(상) | 2. 파일 및 디렉토리 관리 > 2.5 /etc/hosts 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"09\", " >> $postdb 2>&1
	echo "  \"id\" : \"09\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/hosts 파일의 소유자가 root이고, 권한이 600인 이하인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/hosts” 파일의 소유자 및 권한 변경 (소유자 root, 권한 600) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/hosts” 파일의 소유자 및 권한 변경 (소유자 root, 권한 600)\" " >> $action 2>&1
	if [ -f /etc/hosts ]; then
		etc_hosts_owner_name=`ls -l /etc/hosts | awk '{print $3}'`
		if [[ $etc_hosts_owner_name =~ root ]]; then
			etc_hosts_permission=`stat /etc/hosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_hosts_permission -le 600 ]; then
				etc_hosts_owner_permission=`stat /etc/hosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_hosts_owner_permission -eq 0 ] || [ $etc_hosts_owner_permission -eq 2 ] || [ $etc_hosts_owner_permission -eq 4 ] || [ $etc_hosts_owner_permission -eq 6 ]; then
					etc_hosts_group_permission=`stat /etc/hosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_hosts_group_permission -eq 0 ]; then
						etc_hosts_other_permission=`stat /etc/hosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_hosts_other_permission -eq 0 ]; then
							echo " > U-09 결과 : 양호(Good)" >> $resultfile 2>&1
							echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
							echo "  \"결과상세\" : \"/etc/hosts 파일의 소유자가 root이고, 권한이 600인 이하인 경우\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-09 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/hosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/hosts 파일의 소유자가 root이고, 권한이 600인 이하인 경우\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-09 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/hosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/hosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-09 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/hosts 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/hosts 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-09 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/hosts 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/hosts 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-09 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/hosts 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/hosts 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-09 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/hosts 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/hosts 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_10() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-10(상) | 2. 파일 및 디렉토리 관리 > 2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"10\", " >> $postdb 2>&1
	echo "  \"id\" : \"10\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/inetd.conf 파일의 소유자가 root이고, 권한이 600인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/(x)inetd.conf” 파일의 소유자 및 권한 변경 (소유자 root, 권한 600) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/(x)inetd.conf” 파일의 소유자 및 권한 변경 (소유자 root, 권한 600)\" " >> $action 2>&1
	file_exists_count=0
	if [ -f /etc/xinetd.conf ]; then
		((file_exists_count++))
		etc_xinetdconf_owner_name=`ls -l /etc/xinetd.conf | awk '{print $3}'`
		if [[ $etc_xinetdconf_owner_name =~ root ]]; then
			etc_xinetdconf_permission=`stat /etc/xinetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_xinetdconf_permission -ne 600 ]; then
				echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/xinetd.conf 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/xinetd.conf 파일의 권한이 600이 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/xinetd.conf 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/xinetd.conf 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	if [ -d /etc/xinetd.d ]; then
		etc_xinetdd_file_count=`find /etc/xinetd.d -type f 2>/dev/null | wc -l`
		if [ $etc_xinetdd_file_count -gt 0 ]; then
			xinetdd_files=(`find /etc/xinetd.d -type f 2>/dev/null`)
			for ((i=0; i<${#xinetdd_files[@]}; i++))
			do
				xinetdd_file_owner_name=`ls -l ${xinetdd_files[$i]} | awk '{print $3}'`
				if [[ $xinetdd_file_owner_name =~ root ]]; then
					xinetdd_file_permission=`stat ${xinetdd_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
					if [ $xinetdd_file_permission -ne 600 ]; then
						echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/xinetd.d 디렉터리 내 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/xinetd.d 디렉터리 내 파일의 권한이 600이 아닙니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/xinetd.d 디렉터리 내 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/xinetd.d 디렉터리 내 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	fi
	if [ -f /etc/inetd.conf ]; then
		((file_exists_count++))
		etc_inetdconf_owner_name=`ls -l /etc/inetd.conf | awk '{print $3}'`
		if [[ $etc_inetdconf_owner_name =~ root ]]; then
			etc_inetdconf_permission=`stat /etc/inetd.conf | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_inetdconf_permission -ne 600 ]; then
				echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/inetd.conf 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/inetd.conf 파일의 권한이 600이 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-10 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/inetd.conf 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/inetd.conf 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-10 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/(x)inetd.conf 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/(x)inetd.conf 파일이 없습니다.\" " >> $postdb 2>&1
	else
		echo " > U-10 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"/etc/inetd.conf 파일의 소유자가 root이고, 권한이 600인 경우\" " >> $postdb 2>&1
	fi
}



U_11() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-11(상) | 2. 파일 및 디렉토리 관리 > 2.7 /etc/syslog.conf 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"11\", " >> $postdb 2>&1
	echo "  \"id\" : \"11\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/syslog.conf” 파일의 소유자 및 권한 변경 (소유자 root(또는 bin, sys), 권한 644 이하) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/syslog.conf” 파일의 소유자 및 권한 변경 (소유자 root(또는 bin, sys), 권한 644 이하)\" " >> $action 2>&1
	syslogconf_files=("/etc/rsyslog.conf" "/etc/syslog.conf" "/etc/syslog-ng.conf")
	file_exists_count=0
	for ((i=0; i<${#syslogconf_files[@]}; i++))
	do
		if [ -f ${syslogconf_files[$i]} ]; then
			((file_exists_count++))
			syslogconf_file_owner_name=`ls -l ${syslogconf_files[$i]} | awk '{print $3}'`
			if [[ $syslogconf_file_owner_name =~ root ]] || [[ $syslogconf_file_owner_name =~ bin ]] || [[ $syslogconf_file_owner_name =~ sys ]]; then
				syslogconf_file_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
				if [ $syslogconf_file_permission -le 640 ]; then
					syslogconf_file_owner_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
					if [ $syslogconf_file_owner_permission -eq 6 ] || [ $syslogconf_file_owner_permission -eq 4 ] || [ $syslogconf_file_owner_permission -eq 2 ] || [ $syslogconf_file_owner_permission -eq 0 ]; then
						syslogconf_file_group_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
						if [ $syslogconf_file_group_permission -eq 4 ] || [ $syslogconf_file_group_permission -eq 2 ] || [ $syslogconf_file_group_permission -eq 0 ]; then
							syslogconf_file_other_permission=`stat ${syslogconf_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
							if [ $syslogconf_file_other_permission -ne 0 ]; then
								echo " > U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${syslogconf_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${syslogconf_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${syslogconf_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${syslogconf_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${syslogconf_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${syslogconf_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${syslogconf_files[$i]} 파일의 권한이 640보다 큽니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${syslogconf_files[$i]} 파일의 권한이 640보다 큽니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-11 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${syslogconf_files[$i]} 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${syslogconf_files[$i]} 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-11 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/syslog.conf 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/syslog.conf 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-11 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"/etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이하인 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_12() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-12(상) | 2. 파일 및 디렉토리 관리 > 2.8 /etc/services 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"12\", " >> $postdb 2>&1
	echo "  \"id\" : \"12\", " >> $action 2>&1
	echo " 양호 판단 기준 : /etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우"  >> $resultfile 2>&1
	echo "     조치방법 : “/etc/ services” 파일의 소유자 및 권한 변경 (소유자 root(또는 bin, sys), 권한644 이하) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"“/etc/ services” 파일의 소유자 및 권한 변경 (소유자 root(또는 bin, sys), 권한644 이하)\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		etc_services_owner_name=`ls -l /etc/services | awk '{print $3}'`
		if [[ $etc_services_owner_name =~ root ]] || [[ $etc_services_owner_name =~ bin ]] || [[ $etc_services_owner_name =~ sys ]]; then
			etc_services_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_services_permission -le 644 ]; then
				etc_services_owner_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_services_owner_permission -eq 6 ] || [ $etc_services_owner_permission -eq 4 ] || [ $etc_services_owner_permission -eq 2 ] || [ $etc_services_owner_permission -eq 0 ]; then
					etc_services_group_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_services_group_permission -eq 4 ] || [ $etc_services_group_permission -eq 0 ]; then
						etc_services_other_permission=`stat /etc/services | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_services_other_permission -eq 4 ] || [ $etc_services_other_permission -eq 0 ]; then
							echo " > U-12 결과 : 양호(Good)" >> $resultfile 2>&1
							echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
							echo "  \"결과상세\" : \"/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-12 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/services 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/services 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-12 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/services 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/services 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-12 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/services 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/services 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-12 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/services 파일의 권한이 644보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/services 파일의 권한이 644보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-12 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/services 파일의 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/services 파일의 파일의 소유자(owner)가 root(또는 bin, sys)가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-12 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/services 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/services 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_13() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-13(상) | 2. 파일 및 디렉토리 관리 > 2.9 SUID, SGID, 설정 파일점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"13\", " >> $postdb 2>&1
	echo "  \"id\" : \"13\", " >> $action 2>&1
	echo " 양호 판단 기준 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 불필요한 SUID, SGID 파일 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"불필요한 SUID, SGID 파일 제거 - 목록 이외에 애플리케이션에서 생성한 파일이나, 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일의 발견 시 SUID 제거 필요(주요정보통신 가이드 부록 참고)\" " >> $action 2>&1
	executables=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpq-lpd" "/usr/bin/lpr" "/usr/bin/lpr-lpd" "/usr/bin/lprm" "/usr/bin/lprm-lpd" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/lpc-lpd" "/usr/sbin/traceroute")
	for ((i=0; i<${#executables[@]}; i++))
	do
		if [ -f ${executables[$i]} ]; then
			if [ `ls -l ${executables[$i]} | awk '{print substr($1,2,9)}' | grep -i 's' | wc -l` -gt 0 ]; then
				echo " > U-13 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " 주요 실행 파일의 권한에 SUID나 SGID에 대한 설정이 부여되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"주요 실행 파일의 권한에 SUID나 SGID에 대한 설정이 부여되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	echo " > U-13 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우\" " >> $postdb 2>&1
	return 0
}



U_14() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-14(상) | 2. 파일 및 디렉토리 관리 > 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"14\", " >> $postdb 2>&1
	echo "  \"id\" : \"14\", " >> $action 2>&1
	echo " 양호 판단 기준 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여된 경우"  >> $resultfile 2>&1
	echo "     조치방법 : 환경변수 파일의 권한 중 타 사용자 쓰기 권한 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"환경변수 파일의 권한 중 타 사용자 쓰기 권한 제거\" " >> $action 2>&1
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	user_homedirectory_owner_name2=() # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 저장할 빈 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name2[${#user_homedirectory_owner_name2[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_owner_name2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=${user_homedirectory_owner_name2[$i]} # 두 개의 배열 합침
	done
	start_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		for ((j=0; j<${#start_files[@]}; j++))
		do
			if [ -f ${user_homedirectory_path[$i]}/${start_files[$j]} ]; then
				user_homedirectory_owner_name2=`ls -l ${user_homedirectory_path[$i]}/${start_files[$j]} | awk '{print $3}'`
				if [[ $user_homedirectory_owner_name2 =~ root ]] || [[ $user_homedirectory_owner_name2 =~ ${user_homedirectory_owner_name[$i]} ]]; then
					user_homedirectory_other_execute_permission=`ls -l ${user_homedirectory_path[$i]}/${start_files[$j]} | awk '{print substr($1,9,1)}'`
					if [[ $user_homedirectory_other_execute_permission =~ w ]]; then
						echo " > U-14 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일에 다른 사용자(other)의 쓰기(w) 권한이 부여 되어 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일에 다른 사용자(other)의 쓰기(w) 권한이 부여 되어 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-14 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	done
	echo " > U-14 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여된 경우\" " >> $postdb 2>&1
	return 0
}



U_15() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-15(상) | 2. 파일 및 디렉토리 관리 > 2.11 world writable 파일 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"15\", " >> $postdb 2>&1
	echo "  \"id\" : \"15\", " >> $action 2>&1
	echo " 양호 판단 기준 : 시스템 중요 파일에 world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 확인하고 있는 경우"  >> $resultfile 2>&1
	echo "     조치방법 : world writable 파일 존재 여부를 확인하고 불필요한 경우 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"world writable 파일 존재 여부를 확인하고 불필요한 경우 제거\" " >> $action 2>&1
	if [ `find / -type f -perm -2 2>/dev/null | wc -l` -gt 0 ]; then
		echo " > U-15 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " world writable 설정이 되어있는 파일이 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"world writable 설정이 되어있는 파일이 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-15 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"시스템 중요 파일에 world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 확인하고 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_16() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-16(상) | 2. 파일 및 디렉토리 관리 > 2.12 /dev에 존재하지 않는 device 파일 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"16\", " >> $postdb 2>&1
	echo "  \"id\" : \"16\", " >> $action 2>&1
	echo " 양호 판단 기준 : /dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우" >> $resultfile 2>&1
	echo "     조치방법 : major, minor number를 가지지 않는 device 파일 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"major, minor number를 가지지 않는 device 파일 제거\" " >> $action 2>&1
	if [ `find /dev -type f 2>/dev/null | wc -l` -gt 0 ]; then
		echo " > U-16 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " /dev 디렉터리에 존재하지 않는 device 파일이 존재합니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/dev 디렉터리에 존재하지 않는 device 파일이 존재합니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-16 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"/dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_17() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-17(상) | 2. 파일 및 디렉토리 관리 > 2.13 $HOME/.rhosts, hosts.equiv 사용 금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"17\", " >> $postdb 2>&1
	echo "  \"id\" : \"17\", " >> $action 2>&1
	echo " 양호 판단 기준 : login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우" >> $resultfile 2>&1
	echo " 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우" >> $resultfile 2>&1
	echo " 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우" >> $resultfile 2>&1
	echo " 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 ‘+’ 설정이 없는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 홈페이지의 첨부 파일 참고 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \" 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자를 root 또는, 해당 계정으로 변경, 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한을 600 이하로 변경, 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일에서 “+”를 제거하고 반드시 필요한 호스트 및 계정만 등록 (해당 내역 요청)\" " >> $action 2>&1
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	user_homedirectory_owner_name2=() # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 저장할 빈 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name2[${#user_homedirectory_owner_name2[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_owner_name2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=${user_homedirectory_owner_name2[$i]} # 두 개의 배열 합침
	done
	r_command=("rsh" "rlogin" "rexec" "shell" "login" "exec")
	# /etc/xinetd.d 디렉터리 내 r command 파일 확인함
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${r_command[$i]} ]; then
				etc_xinetdd_rcommand_disable_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${r_command[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $etc_xinetdd_rcommand_disable_count -eq 0 ]; then
					if [ -f /etc/hosts.equiv ]; then
						etc_hostsequiv_owner_name=`ls -l /etc/hosts.equiv | awk '{print $3}'`
						if [[ $etc_hostsequiv_owner_name =~ root ]]; then
							etc_hostsequiv_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
							if [ $etc_hostsequiv_permission -le 600 ]; then
								etc_hostsequiv_owner_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
								if [ $etc_hostsequiv_owner_permission -eq 6 ] || [ $etc_hostsequiv_owner_permission -eq 4 ] || [ $etc_hostsequiv_owner_permission -eq 2 ] || [ $etc_hostsequiv_owner_permission -eq 0 ]; then
									etc_hostsequiv_group_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
									if [ $etc_hostsequiv_group_permission -eq 0 ]; then
										etc_hostsequiv_other_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
										if [ $etc_hostsequiv_other_permission -eq 0 ]; then
											etc_hostsequiv_plus_count=`grep -vE '^#|^\s#' /etc/hosts.equiv | grep '+' | wc -l`
											if [ $etc_hostsequiv_plus_count -gt 0 ]; then
												echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
												echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
												echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다.\" " >> $postdb 2>&1
												return 0
											fi
										else
											echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
											echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다.\" " >> $postdb 2>&1
											return 0
										fi
									else
										echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
										echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
										return 0
									fi
								else
									echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
					# 사용자 홈 디렉터리 내 .rhosts 파일 확인함
					for ((j=0; j<${#user_homedirectory_path[@]}; j++))
					do
						if [ -f ${user_homedirectory_path[$j]}/.rhosts ]; then
							user_homedirectory_rhosts_owner_name=`ls -l ${user_homedirectory_path[$j]}/.rhosts | awk '{print $3}'`
							if [[ $user_homedirectory_rhosts_owner_name =~ root ]] || [[ $user_homedirectory_rhosts_owner_name =~ ${user_homedirectory_owner_name[$j]} ]]; then
								user_homedirectory_rhosts_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
								if [ $user_homedirectory_rhosts_permission -le 600 ]; then
									user_homedirectory_rhosts_owner_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
									if [ $user_homedirectory_rhosts_owner_permission -eq 6 ] || [ $user_homedirectory_rhosts_owner_permission -eq 4 ] || [ $user_homedirectory_rhosts_owner_permission -eq 2 ] || [ $user_homedirectory_rhosts_owner_permission -eq 0 ]; then
										user_homedirectory_rhosts_group_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
										if [ $user_homedirectory_rhosts_group_permission -eq 0 ]; then
											user_homedirectory_rhosts_other_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
											if [ $user_homedirectory_rhosts_other_permission -eq 0 ]; then
												user_homedirectory_rhosts_plus_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$j]}/.rhosts | grep '+' | wc -l`
												if [ $user_homedirectory_rhosts_plus_count -gt 0 ]; then
													echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
													echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
													echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
													echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다.\" " >> $postdb 2>&1
													return 0
												fi
											else
												echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
												echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
												echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
												return 0
											fi
										else
											echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
											echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
											return 0
										fi
									else
										echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
										echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
										return 0
									fi
								else
									echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
								return 0
							fi
						fi
					done
				fi
			fi
		done
	fi
	# /etc/inetd.conf 파일 내 r command 서비스 확인함
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			if [ `grep -vE '^#|^\s#' /etc/inetd.conf | grep  ${r_command[$i]} | wc -l` -gt 0 ]; then
				if [ -f /etc/hosts.equiv ]; then
					etc_hostsequiv_owner_name=`ls -l /etc/hosts.equiv | awk '{print $3}'`
					if [[ $etc_hostsequiv_owner_name =~ root ]]; then
						etc_hostsequiv_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
						if [ $etc_hostsequiv_permission -le 600 ]; then
							etc_hostsequiv_owner_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
							if [ $etc_hostsequiv_owner_permission -eq 6 ] || [ $etc_hostsequiv_owner_permission -eq 4 ] || [ $etc_hostsequiv_owner_permission -eq 2 ] || [ $etc_hostsequiv_owner_permission -eq 0 ]; then
								etc_hostsequiv_group_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
								if [ $etc_hostsequiv_group_permission -eq 0 ]; then
									etc_hostsequiv_other_permission=`stat /etc/hosts.equiv | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
									if [ $etc_hostsequiv_other_permission -eq 0 ]; then
										etc_hostsequiv_plus_count=`grep -vE '^#|^\s#' /etc/hosts.equiv | grep '+' | wc -l`
										if [ $etc_hostsequiv_plus_count -gt 0 ]; then
											echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
											echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
											echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일에 '+' 설정이 있습니다.\" " >> $postdb 2>&1
											return 0
										fi
									else
										echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
										echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
										return 0
									fi
								else
									echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, /etc/hosts.equiv 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
				# 사용자 홈 디렉터리 내 .rhosts 파일 확인함
				for ((j=0; j<${#user_homedirectory_path[@]}; j++))
				do
					if [ -f ${user_homedirectory_path[$j]}/.rhosts ]; then
						user_homedirectory_rhosts_owner_name=`ls -l ${user_homedirectory_path[$j]}/.rhosts | awk '{print $3}'`
						if [[ $user_homedirectory_rhosts_owner_name =~ root ]] || [[ $user_homedirectory_rhosts_owner_name =~ ${user_homedirectory_owner_name[$j]} ]]; then
							user_homedirectory_rhosts_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
							if [ $user_homedirectory_rhosts_permission -le 600 ]; then
								user_homedirectory_rhosts_owner_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
								if [ $user_homedirectory_rhosts_owner_permission -eq 6 ] || [ $user_homedirectory_rhosts_owner_permission -eq 4 ] || [ $user_homedirectory_rhosts_owner_permission -eq 2 ] || [ $user_homedirectory_rhosts_owner_permission -eq 0 ]; then
									user_homedirectory_rhosts_group_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
									if [ $user_homedirectory_rhosts_group_permission -eq 0 ]; then
										user_homedirectory_rhosts_other_permission=`stat ${user_homedirectory_path[$j]}/.rhosts | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
										if [ $user_homedirectory_rhosts_other_permission -eq 0 ]; then
											user_homedirectory_rhosts_plus_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$j]}/.rhosts | grep '+' | wc -l`
											if [ $user_homedirectory_rhosts_plus_count -gt 0 ]; then
												echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
												echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
												echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다." >> $resultfile 2>&1
												echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일에 '+' 설정이 있습니다.\" " >> $postdb 2>&1
												return 0
											fi
										else
											echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
											echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
											echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
											echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
											return 0
										fi
									else
										echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
										echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
										echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
										echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
										return 0
									fi
								else
									echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 권한이 600보다 큽니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-17 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"r 계열 서비스를 사용하고, 사용자 홈 디렉터리 내 .rhosts 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				done
			fi
		done
	fi
	echo " > U-17 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우\" " >> $postdb 2>&1
	return 0
}



U_18() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-18(상) | 2. 파일 및 디렉토리 관리 > 2.14 접속 IP 및 포트 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"18\", " >> $postdb 2>&1
	echo "  \"id\" : \"18\", " >> $action 2>&1
	echo " 양호 판단 기준 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우" >> $resultfile 2>&1
	echo "     조치방법 : OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록\" " >> $action 2>&1
	echo " -- /etc/hosts.deny 파일에 ALL:ALL 설정이 없거나 /etc/hosts.allow 파일에 ALL:ALL 설정이 있을 경우 취약으로 판단" >> $resultfile 2>&1
	echo " -- iptables 사용 시 수동 점검을 추가로 진행하세요." >> $resultfile 2>&1
	if [ -f /etc/hosts.deny ]; then
		etc_hostsdeny_allall_count=`grep -vE '^#|^\s#' /etc/hosts.deny | awk '{gsub(" ", "", $0); print}' | grep -i 'all:all' | wc -l`
		if [ $etc_hostsdeny_allall_count -gt 0 ]; then
			if [ -f /etc/hosts.allow ]; then
				etc_hostsallow_allall_count=`grep -vE '^#|^\s#' /etc/hosts.allow | awk '{gsub(" ", "", $0); print}' | grep -i 'all:all' | wc -l`
				if [ $etc_hostsallow_allall_count -gt 0 ]; then
					echo " > U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/hosts.allow 파일에 'ALL : ALL' 설정이 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/hosts.allow 파일에 'ALL : ALL' 설정이 있습니다.\" " >> $postdb 2>&1
					return 0
				else
					echo " > U-18 결과 : 양호(Good)" >> $resultfile 2>&1
					echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
					echo "  \"결과상세\" : \"접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-18 결과 : 양호(Good)" >> $resultfile 2>&1
				echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
				echo "  \"결과상세\" : \"접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/hosts.deny 파일에 'ALL : ALL' 설정이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/hosts.deny 파일에 'ALL : ALL' 설정이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-18 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " /etc/hosts.deny 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/hosts.deny 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_19() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-19(상) | 3. 서비스 관리 > 3.1 Finger 서비스 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"19\", " >> $postdb 2>&1
	echo "  \"id\" : \"19\", " >> $action 2>&1
	echo " 양호 판단 기준 : Finger 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : Finger 서비스 비활성화 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Finger 서비스 비활성화\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		finger_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="finger" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $finger_port_count -gt 0 ]; then
			finger_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="finger" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#finger_port[@]}; i++))
			do
				netstat_finger_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${finger_port[$i]}" | wc -l`
				if [ $netstat_finger_count -gt 0 ]; then
					echo " > U-19 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " finger 서비스가 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"finger 서비스가 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	fi
	ps_finger_count=`ps -ef | grep -i 'finger' | grep -v 'grep' | wc -l`
	if [ $ps_finger_count -gt 0 ]; then
		echo " > U-19 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " finger 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"finger 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-19 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"Finger 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_20() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-20(상) | 3. 서비스 관리 > 3.2 Anonymous FTP 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"20\", " >> $postdb 2>&1
	echo "  \"id\" : \"20\", " >> $action 2>&1
	echo " 양호 판단 기준 : Anonymous FTP (익명 ftp) 접속을 차단한 경우" >> $resultfile 2>&1
	echo "     조치방법 : Anonymous FTP를 사용하지 않는 경우 Anonymous FTP 접속 차단 설정 적용 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Anonymous FTP를 사용하지 않는 경우 Anonymous FTP 접속 차단 설정 적용\" " >> $action 2>&1
	if [ -f /etc/passwd ]; then
		if [ `awk -F : '$1=="ftp" || $1=="anonymous"' /etc/passwd | wc -l` -gt 0 ]; then
			file_exists_count=0
			if [ `find / -name 'proftpd.conf' -type f 2>/dev/null | wc -l` -gt 0 ]; then
				proftpdconf_settings_files=(`find / -name 'proftpd.conf' -type f 2>/dev/null`)
				for ((i=0; i<${#proftpdconf_settings_files[@]}; i++))
				do
					((file_exists_count++))
					proftpdconf_anonymous_start_line_count=`grep -vE '^#|^\s#' ${proftpdconf_settings_files[$i]} | grep '<Anonymous' | wc -l`
					proftpdconf_anonymous_end_line_count=`grep -vE '^#|^\s#' ${proftpdconf_settings_files[$i]} | grep '</Anonymous>' | wc -l`
					if [ $proftpdconf_anonymous_start_line_count -gt 0 ] && [ $proftpdconf_anonymous_end_line_count -gt 0 ]; then
						proftpdconf_anonymous_start_line=`grep -vE '^#|^\s#' ${proftpdconf_settings_files[$i]} | grep -n '<Anonymous' | awk -F : '{print $1}'`
						proftpdconf_anonymous_end_line=`grep -vE '^#|^\s#' ${proftpdconf_settings_files[$i]} | grep -n '</Anonymous>' | awk -F : '{print $1}'`
						proftpdconf_anonymous_contents_range=$((proftpdconf_anonymous_end_line-proftpdconf_anonymous_start_line))
						proftpdconf_anonymous_enable_count=`grep -vE '^#|^\s#' ${proftpdconf_settings_files[$i]} | grep -A $proftpdconf_anonymous_contents_range '<Anonymous' | grep -wE 'User|UserAlias' | wc -l`
						if [ $proftpdconf_anonymous_enable_count -gt 0 ]; then
							echo " > U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${proftpdconf_settings_files[$i]} 파일에서 'User' 또는 'UserAlias' 옵션이 삭제 또는 주석 처리되어 있지 않습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${proftpdconf_settings_files[$i]} 파일에서 'User' 또는 'UserAlias' 옵션이 삭제 또는 주석 처리되어 있지 않습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				done
			fi
			if [ `find / -name 'vsftpd.conf' -type f 2>/dev/null | wc -l` -gt 0 ]; then
				((file_exists_count++))
				vsftpdconf_settings_files=(`find / -name 'vsftpd.conf' -type f 2>/dev/null`)
				settings_in_vsftpdconf=0
				for ((i=0; i<${#vsftpdconf_settings_files[@]}; i++))
				do
					vsftpdconf_anonymous_enable_count=`grep -vE '^#|^\s#' ${vsftpdconf_settings_files[$i]} | grep -i 'anonymous_enable' | wc -l`
					if [ $vsftpdconf_anonymous_enable_count -gt 0 ]; then
						((settings_in_vsftpdconf++))
						vsftpdconf_anonymous_enable_value=`grep -vE '^#|^\s#' ${vsftpdconf_settings_files[$i]} | grep -i 'anonymous_enable' | awk '{gsub(" ", "", $0); print tolower($0)}' | awk -F 'anonymous_enable=' '{print $2}'`
						if [[ $vsftpdconf_anonymous_enable_value =~ yes ]]; then
							echo " > U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${vsftpdconf_settings_files[$i]} 파일에서 익명 ftp 접속을 허용하고 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${vsftpdconf_settings_files[$i]} 파일에서 익명 ftp 접속을 허용하고 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				done
				if [ $settings_in_vsftpdconf -eq 0 ]; then
					echo " > U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " vsftpd.conf 파일에 익명 ftp 접속을 설정하는 옵션이 없습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"vsftpd.conf 파일에 익명 ftp 접속을 설정하는 옵션이 없습니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
			if [ $file_exists_count -eq 0 ]; then
				echo " > U-20 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " 익명 ftp 접속을 설정하는 파일이 없습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"익명 ftp 접속을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	fi
	echo " > U-20 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"Anonymous FTP (익명 ftp) 접속을 차단한 경우\" " >> $postdb 2>&1
	return 0
}



U_21() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-21(상) | 3. 서비스 관리 > 3.3 r 계열 서비스 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"21\", " >> $postdb 2>&1
	echo "  \"id\" : \"21\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요한 r 계열 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : NET Backup등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512) 서비스 중지" >> $resultfile 2>&1
	echo "  \"조치방법\" : \"NET Backup등 특별한 용도로 사용하지 않는다면 shell(514), login(513), exec(512) 서비스 중지\" " >> $action 2>&1
	r_command=("rsh" "rlogin" "rexec" "shell" "login" "exec")
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${r_command[$i]} ]; then
				etc_xinetdd_rcommand_disable_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${r_command[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $etc_xinetdd_rcommand_disable_count -eq 0 ]; then
					echo " > U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " 불필요한 ${r_command[$i]} 서비스가 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"불필요한 ${r_command[$i]} 서비스가 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	fi
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#r_command[@]}; i++))
		do
			etc_inetdconf_enable_count=`grep -vE '^#|^\s#' /etc/inetd.conf | grep ${r_command[$i]} | wc -l`
			if [ $etc_inetdconf_enable_count -gt 0 ]; then
				echo " > U-21 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " 불필요한 ${r_command[$i]} 서비스가 실행 중입니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"불필요한 ${r_command[$i]} 서비스가 실행 중입니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	fi
	echo " > U-21 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"불필요한 r 계열 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_22() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-22(상) | 3. 서비스 관리 > 3.4 crond 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"22\", " >> $postdb 2>&1
	echo "  \"id\" : \"22\", " >> $action 2>&1
	echo " 양호 판단 기준 : crontab 명령어 일반사용자 금지 및 cron 관련 파일 640 이하인 경우" >> $resultfile 2>&1
	echo "     조치방법 : crontab 명령어 750 이하, cron 관련 파일 소유자 및 권한 변경(소유자 root, 권한 640 이하) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"crontab 명령어 750 이하, cron 관련 파일 소유자 및 권한 변경(소유자 root, 권한 640 이하)\" " >> $action 2>&1
	crontab_path=("/usr/bin/crontab" "/usr/sbin/crontab" "/bin/crontab")
	if [ `which crontab 2>/dev/null | wc -l` -gt 0 ]; then
		crontab_path[${#crontab_path[@]}]=`which crontab 2>/dev/null`
	fi
	for ((i=0; i<${#crontab_path[@]}; i++))
	do
		if [ -f ${crontab_path[$i]} ]; then
			crontab_permission=`stat ${crontab_path[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,2)}'` # group, owner 권한만 추출함
			if [ $crontab_permission -le 50 ]; then
				crontab_group_permission=`stat ${crontab_path[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
				if [ $crontab_group_permission -eq 5 ] || [ $crontab_group_permission -eq 4 ] || [ $crontab_group_permission -eq 1 ] || [ $crontab_group_permission -eq 0 ]; then
					crontab_other_permission=`stat ${crontab_path[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
					if [ $crontab_other_permission -ne 0 ]; then
						echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${crontab_path[$i]} 명령어의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  ${crontab_path[$i]} 명령어의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${crontab_path[$i]} 명령어의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${crontab_path[$i]} 명령어의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${crontab_path[$i]} 명령어의 권한이 750보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${crontab_path[$i]} 명령어의 권한이 750보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	cron_directory=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron" "/var/spool/cron/crontabs")
	cron_file=("/etc/crontab" "/etc/cron.allow" "/etc/cron.deny")
	for ((i=0; i<${#cron_directory[@]}; i++))
	do
		cron_file_count=`find ${cron_directory[$i]} -type f 2>/dev/null | wc -l`
		if [ $cron_file_count -gt 0 ]; then
			cron_file2=(`find ${cron_directory[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#cron_file2[@]}; j++))
			do
				cron_file[${#cron_file[@]}]=${cron_file2[$j]}
			done
		fi
	done
	for ((i=0; i<${#cron_file[@]}; i++))
	do
		if [ -f ${cron_file[$i]} ]; then
			cron_file_owner_name=`ls -l ${cron_file[$i]} | awk '{print $3}'`
			if [[ $cron_file_owner_name =~ root ]]; then
				cron_file_permission=`stat ${cron_file[$i]}| grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
				if [ $cron_file_permission -le 640 ]; then
					cron_file_owner_permission=`stat ${cron_file[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
					if [ $cron_file_owner_permission -eq 6 ] || [ $cron_file_owner_permission -eq 4 ] || [ $cron_file_owner_permission -eq 2 ] || [ $cron_file_owner_permission -eq 0 ]; then
						cron_file_group_permission=`stat ${cron_file[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
						if [ $cron_file_group_permission -eq 4 ] || [ $cron_file_group_permission -eq 0 ]; then
							cron_file_other_permission=`stat ${cron_file[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
							if [ $cron_file_other_permission -ne 0 ]; then
								echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${cron_file[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${cron_file[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${cron_file[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${cron_file[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${cron_file[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${cron_file[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${cron_file[$i]} 파일의 권한이 640보다 큽니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${cron_file[$i]} 파일의 권한이 640보다 큽니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-22 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${cron_file[$i]} 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${cron_file[$i]} 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	echo " > U-22 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"crontab 명령어 일반사용자 금지 및 cron 관련 파일 640 이하인 경우\" " >> $postdb 2>&1
	return 0
}


U_23() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-23(상) | 3. 서비스 관리 > 3.5 DoS 공격에 취약한 서비스 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"23\", " >> $postdb 2>&1
	echo "  \"id\" : \"23\", " >> $action 2>&1
	echo " 양호 판단 기준 : 사용하지 않는 DoS 공격에 취약한 서비스가 비활성화된 경우" >> $resultfile 2>&1
	echo "     조치방법 : echo, discard, daytime, charge, ntp, dns, snmp 등 서비스 비활성화 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"echo, discard, daytime, charge, ntp, dns, snmp 등 서비스 비활성화 설정\" " >> $action 2>&1
	services=("echo" "discard" "daytime" "chargen")
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#services[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${services[$i]} ]; then
				etc_xinetdd_service_disable_yes_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${services[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $service_disable_yes_count -eq 0 ]; then
					echo " > U-23 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${services[$i]} 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${services[$i]} 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	fi
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#services[@]}; i++))
		do
			etc_inetdconf_enable_count=`grep -vE '^#|^\s#' /etc/inetd.conf | grep  ${services[$i]} | wc -l`
			if [ $etc_inetdconf_enable_count -gt 0 ]; then
				echo " > U-23 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${services[$i]} 서비스가 /etc/inetd.conf 파일에서 실행 중입니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${services[$i]} 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	fi
	echo " > U-23 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"사용하지 않는 DoS 공격에 취약한 서비스가 비활성화된 경우\" " >> $postdb 2>&1
	return 0
}



U_24() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-24(상) | 3. 서비스 관리 > 3.6 NFS 서비스 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"24\", " >> $postdb 2>&1
	echo "  \"id\" : \"24\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 사용하지 않는다면 NFS 서비스 중지, NFS 서비스를 제거한 후 시스템 부팅 시, 스크립트 실행 방지 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"사용하지 않는다면 NFS 서비스 중지, NFS 서비스를 제거한 후 시스템 부팅 시, 스크립트 실행 방지. 1. /etc/dfs/dfstab(또는 /etx/exports)의 모든 공유 제거, 2. NFS 데몬(nfsd, statd, mountd) 중지, 3. 시동 스크립트 삭제 또는, 스크립트 이름 변경 \" " >> $action 2>&1
	if [ `ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd|' | wc -l` -gt 0 ]; then
		echo " > U-24 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 불필요한 NFS 서비스 관련 데몬이 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"불필요한 NFS 서비스 관련 데몬이 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-24 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_25() {
	echo ""  >> $resultfile 2>&1
	echo " U-25(상) | 3. 서비스 관리 > 3.7 NFS 접근 통제 "  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"25\", " >> $postdb 2>&1
	echo "  \"id\" : \"25\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우" >> $resultfile 2>&1
	echo "     조치방법 : 사용하지 않는다면 NFS 서비스 중지, 사용할 경우 NFS 설정파일에 everyone 공유 설정 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"사용하지 않는다면 NFS 서비스 중지, 사용할 경우 NFS 설정파일에 everyone 공유 설정 제거\" " >> $action 2>&1
	if [ `ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' | grep -ivE 'grep|kblockd|rstatd|' | wc -l` -gt 0 ]; then
		if [ -f /etc/exports ]; then
			etc_exports_all_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep '*' | wc -l`
			etc_exports_insecure_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -i 'insecure' | wc -l`
			etc_exports_directory_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | wc -l`
			etc_exports_squash_count=`grep -vE '^#|^\s#' /etc/exports | grep '/' | grep -iE 'root_squash|all_squash' | wc -l`
			if [ $etc_exports_all_count -gt 0 ]; then
				echo " > U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/exports 파일에 '*' 설정이 있습니다." >> $resultfile 2>&1
				echo " -- '*' 설정 = 모든 클라이언트에 대해 전체 네트워크 공유 허용" >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/exports 파일에 '*' 설정이 있습니다.\" " >> $postdb 2>&1
				return 0
			elif [ $etc_exports_insecure_count -gt 0 ]; then
				echo " > U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다.\" " >> $postdb 2>&1
				return 0
			else
				if [ $etc_exports_directory_count -ne $etc_exports_squash_count ]; then
					echo " > U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		fi
	else
		echo " > U-25 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_26() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-26(상) | 3. 서비스 관리 > 3.8 automountd 제거 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"26\", " >> $postdb 2>&1
	echo "  \"id\" : \"26\", " >> $action 2>&1
	echo " 양호 판단 기준 : automountd 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : automountd 서비스 비활성화 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"automountd 서비스 비활성화\" " >> $action 2>&1
	if [ `ps -ef | grep -iE 'automount|autofs' | grep -v 'grep' | wc -l` -gt 0 ]; then
		echo " > U-26 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " automountd 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"automountd 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-26 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"automountd 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_27() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-27(상) | 3. 서비스 관리 > 3.9 RPC 서비스 확인 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"27\", " >> $postdb 2>&1
	echo "  \"id\" : \"27\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요한 RPC 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 일반적으로 사용하지 않는 RPC 서비스들을 inetd.conf 파일에서 주석 처리한 후 inetd 재구동 (진단 보고서에 발견된 RPC 서비스 조치) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"일반적으로 사용하지 않는 RPC 서비스들을 inetd.conf 파일에서 주석 처리한 후 inetd 재구동 (진단 보고서에 발견된 RPC 서비스 조치)\" " >> $action 2>&1
	rpc_services=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#rpc_services[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${rpc_services[$i]} ]; then
				etc_xinetdd_rpcservice_disable_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${rpc_services[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $etc_xinetdd_rpcservice_disable_count -eq 0 ]; then
					echo " > U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " 불필요한 RPC 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"불필요한 RPC 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	fi
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#rpc_services[@]}; i++))
		do
			etc_inetdconf_rpcservice_enable_count=`grep -vE '^#|^\s#' /etc/inetd.conf | grep -w ${rpc_services[$i]} | wc -l`
			if [ $etc_inetdconf_rpcservice_enable_count -gt 0 ]; then
				echo " > U-27 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " 불필요한 RPC 서비스가 /etc/inetd.conf 파일에서 실행 중입니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"불필요한 RPC 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	fi
	echo " > U-27 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"불필요한 RPC 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_28() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-28(상) | 3. 서비스 관리 > 3.10 NIS, NIS+ 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"28\", " >> $postdb 2>&1
	echo "  \"id\" : \"28\", " >> $action 2>&1
	echo " 양호 판단 기준 : NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우" >> $resultfile 2>&1
	echo "     조치방법 : NIS 관련 서비스 비활성화 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"NIS 관련 서비스 비활성화\" " >> $action 2>&1
	if [ `ps -ef | grep -iE 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v 'grep' | wc -l` -gt 0 ]; then
		echo " > U-28 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " NIS 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"NIS 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-28 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_29() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-29(상) | 3. 서비스 관리 > 3.11 tftp, talk 서비스 비활성화 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"29\", " >> $postdb 2>&1
	echo "  \"id\" : \"29\", " >> $action 2>&1
	echo " 양호 판단 기준 : tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 시스템 운영에 불필요한 서비스(tftp, talk, ntalk) 비활성화 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"시스템 운영에 불필요한 서비스(tftp, talk, ntalk) 비활성화\" " >> $action 2>&1
	services=("tftp" "talk" "ntalk")
	if [ -d /etc/xinetd.d ]; then
		for ((i=0; i<${#services[@]}; i++))
		do
			if [ -f /etc/xinetd.d/${services[$i]} ]; then
				etc_xinetdd_service_disable_count=`grep -vE '^#|^\s#' /etc/xinetd.d/${services[$i]} | grep -i 'disable' | grep -i 'yes' | wc -l`
				if [ $etc_xinetdd_service_disable_count -eq 0 ]; then
					echo " > U-29 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${services[$i]} 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${services[$i]} 서비스가 /etc/xinetd.d 디렉터리 내 서비스 파일에서 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	fi
	if [ -f /etc/inetd.conf ]; then
		for ((i=0; i<${#services[@]}; i++))
		do
			etc_inetdconf_service_enable_count=`grep -vE '^#|^\s#' /etc/inetd.conf | grep ${services[$i]} | wc -l`
			if [ $etc_inetdconf_service_enable_count -gt 0 ]; then
				echo " > U-29 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${services[$i]} 서비스가 /etc/inetd.conf 파일에서 실행 중입니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"{services[$i]} 서비스가 /etc/inetd.conf 파일에서 실행 중입니다.\" " >> $postdb 2>&1
				return 0
			fi
		done
	fi
	echo " > U-29 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_30() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-30(상) | 3. 서비스 관리 > 3.12 Sendmail 버전 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"30\", " >> $postdb 2>&1
	echo "  \"id\" : \"30\", " >> $action 2>&1
	echo " 양호 판단 기준 : Sendmail 버전이 최신버전인 경우" >> $resultfile 2>&1
	echo "     조치방법 : Sendmail 서비스를 사용하지 않을 경우 서비스 중지, 재부팅 후 다시 시작하지 않도록 시작 스크립트 변경, 사용할 경우 패치 관리 정책을 수립하여 주기적으로 패치 적용 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Sendmail 서비스를 사용하지 않을 경우 서비스 중지, 재부팅 후 다시 시작하지 않도록 시작 스크립트 변경, 사용할 경우 패치 관리 정책을 수립하여 주기적으로 패치 적용\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $smtp_port_count -gt 0 ]; then
			smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#smtp_port[@]}; i++))
			do
				netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]}" | wc -l`
				if [ $netstat_smtp_count -gt 0 ]; then
					rpm_smtp_version=`rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}'`
					dnf_smtp_version=`dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}'`
					if [[ $rpm_smtp_version != 8.17.1* ]] && [[ $dnf_smtp_version != 8.17.1* ]]; then
						echo " > U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " sendmail 버전이 최신 버전(8.17.1)이 아닙니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"endmail 버전이 최신 버전(8.17.1)이 아닙니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
	if [ $ps_smtp_count -gt 0 ]; then
		rpm_smtp_version=`rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}'`
		dnf_smtp_version=`dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}'`
		if [[ $rpm_smtp_version != 8.17.1* ]] && [[ $dnf_smtp_version != 8.17.1* ]]; then
			echo " > U-30 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " sendmail 버전이 최신 버전(8.17.1)이 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"sendmail 버전이 최신 버전(8.17.1)이 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-30 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"양호 판단 기준 : Sendmail 버전이 최신버전인 경우\" " >> $postdb 2>&1
	return 0
}



U_31() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-31(상) | 3. 서비스 관리 > 3.13 스팸 메일 릴레이 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"31\", " >> $postdb 2>&1
	echo "  \"id\" : \"31\", " >> $action 2>&1
	echo " 양호 판단 기준 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : Sendmail 서비스를 사용하지 않을 경우 서비스 중지, 사용할 경우 릴레이 방지 설정 또는, 릴레이 대상 접근 제어 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Sendmail 서비스를 사용하지 않을 경우 서비스 중지, 사용할 경우 릴레이 방지 설정 또는, 릴레이 대상 접근 제어\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $smtp_port_count -gt 0 ]; then
			smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#smtp_port[@]}; i++))
			do
				netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]}" | wc -l`
				if [ $netstat_smtp_count -gt 0 ]; then
					sendmailcf_exists_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
					if [ $sendmailcf_exists_count -gt 0 ]; then
						sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
						if [ ${#sendmailcf_files[@]} -gt 0 ]; then
							for ((j=0; j<${#sendmailcf_files[@]}; j++))
							do
								sendmailcf_relaying_denied_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$j]} | grep -i 'R$\*' | grep -i 'Relaying denied' | wc -l`
								if [ $sendmailcf_relaying_denied_count -eq 0 ]; then
									echo " > U-31 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " ${sendmailcf_files[$j]} 파일에 릴레이 제한이 설정되어 있지 않습니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"${sendmailcf_files[$j]} 파일에 릴레이 제한이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
									return 0
								fi
							done
						fi
					fi
				fi
			done
		fi
	fi
	ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
	if [ $ps_smtp_count -gt 0 ]; then
		sendmailcf_exists_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
		if [ $sendmailcf_exists_count -gt 0 ]; then
			sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
			if [ ${#sendmailcf_files[@]} -gt 0 ]; then
				for ((i=0; i<${#sendmailcf_files[@]}; i++))
				do
					sendmailcf_relaying_denied_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$i]} | grep -i 'R$\*' | grep -i 'Relaying denied' | wc -l`
					if [ $sendmailcf_relaying_denied_count -eq 0 ]; then
						echo " > U-31 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${sendmailcf_files[$i]} 파일에 릴레이 제한이 설정되어 있지 않습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${sendmailcf_files[$j]} 파일에 릴레이 제한이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
						return 0
					fi
				done
			fi
		fi
	fi
	echo " > U-31 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_32() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-32(상) | 3. 서비스 관리 > 3.14 일반사용자의 Sendmail 실행 방지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"32\", " >> $postdb 2>&1
	echo "  \"id\" : \"32\", " >> $action 2>&1
	echo " 양호 판단 기준 : SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정된 경우" >> $resultfile 2>&1
	echo "     조치방법 : Sendmail 서비스를 사용하지 않을 경우 서비스 중지, Sendmail 서비스를 사용 시 sendmail.cf 설정파일에 restrictqrun 옵션 추가 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"조치방법 : Sendmail 서비스를 사용하지 않을 경우 서비스 중지, Sendmail 서비스를 사용 시 sendmail.cf 설정파일에 restrictqrun 옵션 추가 설정\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $smtp_port_count -gt 0 ]; then
			smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#smtp_port[@]}; i++))
			do
				netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]} " | wc -l`
				if [ $netstat_smtp_count -gt 0 ]; then
					sendmailcf_exists_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
					if [ $sendmailcf_exists_count -gt 0 ]; then
						sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
						for ((j=0; j<${#sendmailcf_files[@]}; j++))
						do
							sendmailcf_file_restrictqrun_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$j]} | awk '{gsub(" ", "", $0); print tolower($0)}' | awk -F 'privacyoptions=' '{print $2}' | grep 'restrictqrun' | wc -l`
							if [ $sendmailcf_file_restrictqrun_count -eq 0 ]; then
								echo " > U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo " ${sendmailcf_files[$j]} 파일에 restrictqrun 옵션이 설정되어 있지 않습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${sendmailcf_files[$j]} 파일에 restrictqrun 옵션이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					else
						echo " > U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " sendmail.cf 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"sendmail.cf 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
	if [ $ps_smtp_count -gt 0 ]; then
		sendmailcf_exists_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
		if [ $sendmailcf_exists_count -gt 0 ]; then
			sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
			for ((i=0; i<${#sendmailcf_files[@]}; i++))
			do
				sendmailcf_file_restrictqrun_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$i]} | awk '{gsub(" ", "", $0); print tolower($0)}' | awk -F 'privacyoptions=' '{print $2}' | grep 'restrictqrun' | wc -l`
				if [ $sendmailcf_file_restrictqrun_count -eq 0 ]; then
					echo " > U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${sendmailcf_files[$i]} 파일에 restrictqrun 옵션이 설정되어 있지 않습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${sendmailcf_files[$i]} 파일에 restrictqrun 옵션이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		else
			echo " > U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " sendmail.cf 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"sendmail.cf 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-32 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정된 경우\" " >> $postdb 2>&1
	return 0
}



U_33() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-33(상) | 3. 서비스 관리 > 3.15 DNS 보안 버전 패치 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"33\", " >> $postdb 2>&1
	echo "  \"id\" : \"33\", " >> $action 2>&1
	echo " 양호 판단 기준 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우" >> $resultfile 2>&1
	echo " -- 9.19 이상 버전은 개발 및 테스트 중이므로 9.18 버전으로 점검" >> $resultfile 2>&1
	echo "     조치방법 : DNS 서비스를 사용하지 않을 경우 서비스 중지, 사용할 경우 패치 관리 정책을 수립하여 주기적으로 패치 적용 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"DNS 서비스를 사용하지 않을 경우 서비스 중지, 사용할 경우 패치 관리 정책을 수립하여 주기적으로 패치 적용\" " >> $action 2>&1
	ps_dns_count=`ps -ef | grep -i 'named' | grep -v 'grep' | wc -l`
	if [ $ps_dns_count -gt 0 ]; then
		rpm_bind9_minor_version=(`rpm -qa 2>/dev/null | grep '^bind' | awk -F '9.' '{print $2}' | grep -v '^$' | uniq`)
		dnf_bind_major_minor_version=(`dnf list installed bind* 2>/dev/null | grep -v 'Installed Packages' | awk -F : '{print $2}' | grep -v '^$' | uniq`)
		if [ ${#rpm_bind9_minor_version[@]} -gt 0 ] && [ ${#dnf_bind_major_minor_version[@]} -gt 0 ]; then
			for ((i=0; i<${#rpm_bind9_minor_version[@]}; i++))
			do
				if [[ ${rpm_bind9_minor_version[$i]} =~ 18.* ]]; then
					rpm_bind9_patch_version=(`rpm -qa 2>/dev/null | grep '^bind' | awk -F '18.' '{print $2}' | grep -v '^$' | uniq`)
					if [ ${#rpm_bind9_patch_version[@]} -gt 0 ]; then
						for ((j=0; j<${#rpm_bind9_patch_version[@]}; j++))
						do
							if [[ ${rpm_bind9_patch_version[$j]} != [7-9]* ]] || [[ ${rpm_bind9_patch_version[$j]} != 1[0-6]* ]]; then
								echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					else
						echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
			for ((i=0; i<${#dnf_bind_major_minor_version[@]}; i++))
			do
				if [[ ${dnf_bind_major_minor_version[$i]} =~ 9.18.* ]]; then
					dnf_bind_patch_version=(`dnf list installed bind* 2>/dev/null | grep -v 'Installed Packages' | awk -F : '{print $2}' | awk -F '18.' '{print $2}' | grep -v '^$' | uniq`)
					if [ ${#dnf_bind_patch_version[@]} -gt 0 ]; then
						for ((j=0; j<${#dnf_bind_patch_version[@]}; j++))
						do
							if [[ ${dnf_bind_patch_version[$j]} != [7-9]* ]] || [[ ${dnf_bind_patch_version[$j]} != 1[0-6]* ]]; then
								echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					else
						echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		else
			echo " > U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi		
	fi
	echo " > U-33 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_34() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-34(상) | 3. 서비스 관리 > 3.16 DNS Zone Transfer 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"34\", " >> $postdb 2>&1
	echo "  \"id\" : \"34\", " >> $action 2>&1
	echo " 양호 판단 기준 : DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우" >> $resultfile 2>&1
	echo "     조치방법 : DNS 서비스를 사용하지 않을 경우 서비스 중지, 사용한다면 DNS 설정을 통해 내부 Zone 파일을 임의의 외부 서버에서 전송 받지 못하게 하고, 아무나 쿼리 응답을 받을 수 없도록 수정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"DNS 서비스를 사용하지 않을 경우 서비스 중지, 사용한다면 DNS 설정을 통해 내부 Zone 파일을 임의의 외부 서버에서 전송 받지 못하게 하고, 아무나 쿼리 응답을 받을 수 없도록 수정\" " >> $action 2>&1
	ps_dns_count=`ps -ef | grep -i 'named' | grep -v 'grep' | wc -l`
	if [ $ps_dns_count -gt 0 ]; then
		if [ -f /etc/named.conf ]; then
			etc_namedconf_allowtransfer_count=`grep -vE '^#|^\s#' /etc/named.conf | grep -i 'allow-transfer' | grep -i 'any' | wc -l`
			if [ $etc_namedconf_allowtransfer_count -gt 0 ]; then
				echo " > U-34 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/named.conf 파일에 allow-transfer { any; } 설정이 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/named.conf 파일에 allow-transfer { any; } 설정이 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"\" " >> $postdb 2>&1
				return 0
			fi
		fi
	fi
	echo " > U-34 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우\" " >> $postdb 2>&1
	return 0
}



U_35() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-35(상) | 3. 서비스 관리 > 3.17 웹서비스 디렉토리 리스팅 제거 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"35\", " >> $postdb 2>&1
	echo "  \"id\" : \"35\", " >> $action 2>&1
	echo " 양호 판단 기준 : 디렉터리 검색 기능을 사용하지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 디렉터리 검색 기능 제거 (/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 Options 지시자에서 Indexes 옵션 제거) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"디렉터리 검색 기능 제거 (/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 Options 지시자에서 Indexes 옵션 제거)\" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf" "userdir.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				if [[ ${find_webconf_files[$j]} =~ userdir.conf ]]; then
					userdirconf_disabled_count=`grep -vE '^#|^\s#'  ${find_webconf_files[$j]} | grep -i 'userdir' | grep -i 'disabled' | wc -l`
					if [ $userdirconf_disabled_count -eq 0 ]; then
						userdirconf_indexes_count=`grep -vE '^#|^\s#'  ${find_webconf_files[$j]} | grep -i 'Options' | grep -iv '\-indexes' | grep -i 'indexes' | wc -l`
						if [ $userdirconf_indexes_count -gt 0 ]; then
							echo " > U-35 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " Apache 설정 파일에 디렉터리 검색 기능을 사용하도록 설정되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"Apache 설정 파일에 디렉터리 검색 기능을 사용하도록 설정되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				else
					webconf_file_indexes_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'Options' | grep -iv '\-indexes' | grep -i 'indexes' | wc -l`
					if [ $webconf_file_indexes_count -gt 0 ]; then
						echo " > U-35 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " Apache 설정 파일에 디렉터리 검색 기능을 사용하도록 설정되어 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"Apache 설정 파일에 디렉터리 검색 기능을 사용하도록 설정되어 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	done
	echo " > U-35 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"디렉터리 검색 기능을 사용하지 않는 경우\" " >> $postdb 2>&1
	return 0
}



U_36() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-36(상) | 3. 서비스 관리 > 3.18 웹서비스 웹 프로세스 권한 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"36\", " >> $postdb 2>&1
	echo "  \"id\" : \"36\", " >> $action 2>&1
	echo " 양호 판단 기준 : Apache 데몬이 root 권한으로 구동되지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : Apache 데몬을 root 가 아닌 별도 계정으로 구동 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Apache 데몬을 root 가 아닌 별도 계정으로 구동\" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				webconf_file_group_root_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -B 1 '^\s*Group' | grep 'root' | wc -l`
				if [ $webconf_file_group_root_count -gt 0 ]; then
					echo " > U-36 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " Apache 데몬이 root 권한으로 구동되도록 설정되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"Apache 데몬이 root 권한으로 구동되도록 설정되어 있습니다.\" " >> $postdb 2>&1
					return 0
				else
					webconf_file_group_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep '^\s*Group' | awk '{print $2}' | sed 's/{//' | sed 's/}//' | wc -l`
					if [ $webconf_file_group_count -gt 0 ]; then
						webconf_file_group=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep '^\s*Group' | awk '{print $2}' | sed 's/{//' | sed 's/}//'`
						webconf_file_group_root_count=`eval echo $webconf_file_group | grep 'root' | wc -l`
						if [ $webconf_file_group_root_count -gt 0 ]; then
							echo " > U-36 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " Apache 데몬이 root 권한으로 구동되도록 설정되어 있습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"Apache 데몬이 root 권한으로 구동되도록 설정되어 있습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				fi
			done
		fi
	done
	echo " > U-36 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"Apache 데몬이 root 권한으로 구동되지 않는 경우\" " >> $postdb 2>&1
	return 0
}



U_37() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-37(상) | 3. 서비스 관리 > 3.19 웹서비스 상위 디렉토리 접근 금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"37\", " >> $postdb 2>&1
	echo "  \"id\" : \"37\", " >> $action 2>&1
	echo " 양호 판단 기준 : 상위 디렉터리에 이동제한을 설정한 경우" >> $resultfile 2>&1
	echo "     조치방법 : 디렉터리에 이동제한(자료 참조) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"1. 사용자 인증을 하기 위해서 각 디렉터리 별로 httpd.conf 파일 내 AllowOverride 지시자의 옵션 설정을 변경 (None에서 AuthConfig 또는, All로 변경), 2. 사용자 인증을 설정할 디렉터리에 .htaccess 파일 생성, 3. 사용자 인증 계정 생성: htpasswd -c <인증 파일> <사용자 계정> \" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf" "userdir.conf")
	file_exists_count=0
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			((file_exists_count++))
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				if [[ ${find_webconf_files[$j]} =~ userdir.conf ]]; then
					userdirconf_disabled_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'userdir' | grep -i 'disabled' | wc -l`
					if [ $userdirconf_disabled_count -eq 0 ]; then
						userdirconf_allowoverride_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'AllowOverride' | wc -l`
						if [ $userdirconf_allowoverride_count -gt 0 ]; then
							userdirconf_allowoverride_none_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'AllowOverride' | grep -i 'None' | wc -l`
							if [ $userdirconf_allowoverride_none_count -gt 0 ]; then
								echo " > U-37 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " 웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-37 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " 웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				else
					webconf_file_allowoverride_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'AllowOverride' | wc -l`
					if [ $webconf_file_allowoverride_count -gt 0 ]; then
						webconf_file_allowoverride_none_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'AllowOverride' | grep -i 'None' | wc -l`
						if [ $webconf_file_allowoverride_none_count -gt 0 ]; then
							echo " > U-37 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " 웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-37 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " 웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"웹 서비스 상위 디렉터리에 이동 제한을 설정하지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	done
	ps_apache_count=`ps -ef | grep -iE 'httpd|apache2' | grep -v 'grep' | wc -l`
	if [ $ps_apache_count -gt 0 ] && [ $file_exists_count -eq 0 ]; then
		echo " > U-37 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " Apache 서비스를 사용하고, 웹 서비스 상위 디렉터리에 이동 제한을 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"Apache 서비스를 사용하고, 웹 서비스 상위 디렉터리에 이동 제한을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-37 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"상위 디렉터리에 이동제한을 설정한 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_38() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-38(상) | 3. 서비스 관리 > 3.20 웹서비스 불필요한 파일 제거 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"38\", " >> $postdb 2>&1
	echo "  \"id\" : \"38\", " >> $action 2>&1
	echo " 양호 판단 기준 : 기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 불필요한 파일 및 디렉터리 제거(“/[Apache_home]/htdocs/manual”, “/[Apache_home]/manual” 파일 제거 등) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"불필요한 파일 및 디렉터리 제거(“/[Apache_home]/htdocs/manual”, “/[Apache_home]/manual” 파일 제거 등)\" " >> $action 2>&1
	serverroot_directory=()
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				webconf_serverroot_count=$(grep -vE '^#|^\s#' "${find_webconf_files[$j]}" | grep 'ServerRoot' | grep '/' | wc -l)
				if [ "$webconf_serverroot_count" -gt 0 ]; then
   					serverroot_directory[${#serverroot_directory[@]}]=$(grep -vE '^#|^\s#' "${find_webconf_files[$j]}" | grep 'ServerRoot' | grep '/' | awk '{gsub(/"/, "", $0); print $2}')
				fi
			done

		fi
	done
	apache2_serverroot_count=`apache2 -V 2>/dev/ull | grep -i 'root' | awk -F '"' '{gsub(" ", "", $0); print $2}' | wc -l`
	if [ $apache2_serverroot_count -gt 0 ];then
		serverroot_directory[${#serverroot_directory[@]}]=`apache2 -V 2>/dev/ull | grep -i 'root' | awk -F '"' '{gsub(" ", "", $0); print $2}'`
	fi
	httpd_serverroot_count=`httpd -V 2>/dev/ull | grep -i 'root' | awk -F '"' '{gsub(" ", "", $0); print $2}' | wc -l`
	if [ $httpd_serverroot_count -gt 0 ]; then
		serverroot_directory[${#serverroot_directory[@]}]=`httpd -V 2>/dev/ull | grep -i 'root' | awk -F '"' '{gsub(" ", "", $0); print $2}'`
	fi
	for ((i=0; i<${#serverroot_directory[@]}; i++))
	do
		manual_file_exists_count=`find ${serverroot_directory[$i]} -name 'manual' -type f 2>/dev/null | wc -l`
		if [ $manual_file_exists_count -gt 0 ]; then
			echo " > U-38 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " Apache 홈 디렉터리 내 기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되어 있지 않습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"Apache 홈 디렉터리 내 기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되어 있지 않습니다.\" " >> $postdb 2>&1
			return 0
		fi
	done
	echo " > U-38 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_39() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-39(상) | 3. 서비스 관리 > 3.21 웹서비스 링크 사용금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"39\", " >> $postdb 2>&1
	echo "  \"id\" : \"39\", " >> $action 2>&1
	echo " 양호 판단 기준 : 심볼릭 링크, aliases 사용을 제한한 경우" >> $resultfile 2>&1
	echo "     조치방법 : 심볼릭 링크, aliases 사용 제한(/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 Options 지시자에서 심볼릭 링크를 가능하게 하는 FollowSymLinks 옵션 제거) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"심볼릭 링크, aliases 사용 제한(/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 Options 지시자에서 심볼릭 링크를 가능하게 하는 FollowSymLinks 옵션 제거)\" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf" "userdir.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				if [[ ${find_webconf_files[$j]} =~ userdir.conf ]]; then
					userdirconf_disabled_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'userdir' | grep -i 'disabled' | wc -l`
					if [ $userdirconf_disabled_count -eq 0 ]; then
						userdirconf_followsymlinks_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'Options' | grep -iv '\-FollowSymLinks' | grep -i 'FollowSymLinks' | wc -l`
						if [ $userdirconf_followsymlinks_count -gt 0 ]; then
							echo " > U-39 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " Apache 설정 파일에 심볼릭 링크 사용을 제한하도록 설정하지 않습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"Apache 설정 파일에 심볼릭 링크 사용을 제한하도록 설정하지 않습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				else
					webconf_file_followSymlinks_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'Options' | grep -iv '\-FollowSymLinks' | grep -i 'FollowSymLinks' | wc -l`
					if [ $webconf_file_followSymlinks_count -gt 0 ]; then
						echo " > U-39 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " Apache 설정 파일에 심볼릭 링크 사용을 제한하도록 설정하지 않습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"Apache 설정 파일에 심볼릭 링크 사용을 제한하도록 설정하지 않습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	done
	echo " > U-39 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"심볼릭 링크, aliases 사용을 제한한 경우\" " >> $postdb 2>&1
	return 0
}



U_40() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-40(상) | 3. 서비스 관리 > 3.22 웹서비스 파일 업로드 및 다운로드 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"40\", " >> $postdb 2>&1
	echo "  \"id\" : \"40\", " >> $action 2>&1
	echo " 양호 판단 기준 : 파일 업로드 및 다운로드를 제한한 경우" >> $resultfile 2>&1
	echo "     조치방법 : 파일 업로드 및 다운로드 용량 제한 (/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 LimitRequestBody 지시자에 파일 사이즈 용량 제한 설정) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"파일 업로드 및 다운로드 용량 제한 (/[Apache_home]/conf/httpd.conf 파일에 설정된 모든 디렉터리의 LimitRequestBody 지시자에 파일 사이즈 용량 제한 설정)\" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf" "userdir.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				if [[ ${find_webconf_files[$j]} =~ userdir.conf ]]; then
					userdirconf_disabled_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'userdir' | grep -i 'disabled' | wc -l`
					if [ $userdirconf_disabled_count -eq 0 ]; then
						userdirconf_limitrequestbody_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'LimitRequestBody' | wc -l`
						if [ $userdirconf_limitrequestbody_count -eq 0 ]; then
							echo " > U-40 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " Apache 설정 파일에 파일 업로드 및 다운로드를 제한하도록 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"Apache 설정 파일에 파일 업로드 및 다운로드를 제한하도록 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
				else
					webconf_limitrequestbody_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'LimitRequestBody' | wc -l`
					if [ $webconf_limitrequestbody_count -eq 0 ]; then
						echo " > U-40 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " Apache 설정 파일에 파일 업로드 및 다운로드를 제한하도록 설정하지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"Apache 설정 파일에 파일 업로드 및 다운로드를 제한하도록 설정하지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	done
	echo " > U-40 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"파일 업로드 및 다운로드를 제한한 경우\" " >> $postdb 2>&1
	return 0
}



U_41() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-41(상) | 3. 서비스 관리 > 3.23 웹서비스 영역의 분리 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"41\", " >> $postdb 2>&1
	echo "  \"id\" : \"41\", " >> $action 2>&1
	echo " 양호 판단 기준 : DocumentRoot를 별도의 디렉터리로 지정한 경우" >> $resultfile 2>&1
	echo "     조치방법 :  DocumentRoot /usr/local/apache/htdocs, /usr/local/apache2/htdocs, /var/www/html와 같이 기본경로일 경우 -> etc, bin, sbin, usr 등 시스템 중요 디렉터리 외에 설치(예 : /www 와 같이 별도의 디렉터리를 생성하여 설치, 운영) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"/usr/local/apache/htdocs, /usr/local/apache2/htdocs, /var/www/html와 같이 기본경로일 경우 -> etc, bin, sbin, usr 등 시스템 중요 디렉터리 외에 설치(예 : /www 와 같이 별도의 디렉터리를 생성하여 설치, 운영)\" " >> $action 2>&1
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf")
	file_exists_count=0
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			((file_exists_count++))
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				webconf_file_documentroot_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'DocumentRoot' | grep '/' | wc -l`
				if [ $webconf_file_documentroot_count -gt 0 ]; then
					webconf_file_documentroot_basic_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'DocumentRoot' | grep '/' | awk '{gsub(/"/, "", $0); print $2}' | grep -E '/usr/local/apache/htdocs|/usr/local/apache2/htdocs|/var/www/html' | wc -l`
					if [ $webconf_file_documentroot_basic_count -gt 0 ]; then 
						echo " > U-41 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " Apache DocumentRoot를 기본 디렉터리로 설정했습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"Apache DocumentRoot를 기본 디렉터리로 설정했습니다.\" " >> $postdb 2>&1

						return 0
					fi
				else
					echo " > U-41 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " Apache DocumentRoot를 설정하지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"Apache DocumentRoot를 설정하지 않았습니다.\" " >> $postdb 2>&1

					return 0
				fi
			done
		fi
	done
	ps_apache_count=`ps -ef | grep -iE 'httpd|apache2' | grep -v 'grep' | wc -l`
	if [ $ps_apache_count -gt 0 ] && [ $file_exists_count -eq 0 ]; then
		echo " > U-41 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " Apache 서비스를 사용하고, DocumentRoot를 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"Apache 서비스를 사용하고, DocumentRoot를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1

		return 0
	else
		echo " > U-41 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"DocumentRoot를 별도의 디렉터리로 지정한 경우\" " >> $postdb 2>&1

		return 0
	fi
}



U_42() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-42(상) | 4 패치 관리 > 4.1 최신 보안패치 및 벤더 권고사항 적용 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"패치 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"42\", " >> $postdb 2>&1
	echo "  \"id\" : \"42\", " >> $action 2>&1
	echo " 양호 판단 기준 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 하고 있으며, 패치 관련 내용을 확인하고 적용했을 경우" >> $resultfile 2>&1
	echo "     조치방법 : O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용함 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"O/S 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 파악하여 OS 관리자 및 벤더에서 적용함\" " >> $action 2>&1
	echo " > U-42 결과 : N/A" >> $resultfile 2>&1
	echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
	echo " 수동으로 점검하세요." >> $resultfile 2>&1
	echo "  \"결과상세\" : \"수동으로 점검하세요.\" " >> $postdb 2>&1


}



U_43() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-43(상) | 5. 로그 관리 > 5.1 로그의 정기적 검토 및 보고 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"로그 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"43\", " >> $postdb 2>&1
	echo "  \"id\" : \"43\", " >> $action 2>&1
	echo " 양호 판단 기준 : 접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 로그 기록 검토 및 분석을 시행하여 리포트를 작성하고 정기적으로 보고함 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"로그 기록 검토 및 분석을 시행하여 리포트를 작성하고 정기적으로 보고함\" " >> $action 2>&1
	echo " > U-43 결과 : N/A" >> $resultfile 2>&1
	echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
	echo " 수동으로 점검하세요." >> $resultfile 2>&1
	echo "  \"결과상세\" : \"수동으로 점검하세요.\" " >> $postdb 2>&1
}



U_44() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-44(중) | 1. 계정관리 > 1.5 root 이외의 UID가 '0' 금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"44\", " >> $postdb 2>&1
	echo "  \"id\" : \"44\", " >> $action 2>&1
	echo " 양호 판단 기준 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : UID가 0인 계정 존재 시 변경할 UID를 확인 후 다른 UID로 변경 및 불필요 시 삭제, 계정이 사용 중이면 명령어로 조치가 안 되므로 /etc/passwd 파일 설정 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"UID가 0인 계정 존재 시 변경할 UID를 확인 후 다른 UID로 변경 및 불필요 시 삭제, 계정이 사용 중이면 명령어로 조치가 안 되므로 /etc/passwd 파일 설정 변경 \" " >> $action 2>&1
	if [ -f /etc/passwd ]; then
		if [ `awk -F : '$3==0 {print $1}' /etc/passwd | grep -vx 'root' | wc -l` -gt 0 ]; then
			echo " > U-44 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"root 계정과 동일한 UID(0)를 갖는 계정이 존재합니다.\" " >> $postdb 2>&1
			return 0
		else
			echo " > U-44 결과 : 양호(Good)" >> $resultfile 2>&1
			echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
			echo "  \"결과상세\" : \"root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우\" " >> $postdb 2>&1
			return 0
		fi
	fi
}



U_45() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-45(하) | 1. 계정관리 > 1.6 root 계정 su 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"45\", " >> $postdb 2>&1
	echo "  \"id\" : \"45\", " >> $action 2>&1
	echo " 양호 판단 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우" >> $resultfile 2>&1
	# pam_rootok.so( : 루트 유저가 인증하려고 하는 당사자인지 확인)모듈을 사용하지 않는 경우 U_45 함수 수정 필요
	# pam_rootok.so 모듈 사용과 함께 trust 문구를 추가한 경우 U_45 함수 수정 필요
	echo "     조치방법 : 일반 사용자의 su 명령 사용 제한 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"일반 사용자의 su 명령 사용 제한. 1. Group 생성(생성할 그룹 요청, 일반적으로 wheel 사용), 2. su 명령어의 그룹을 su 명령어 허용할 그룹으로 변경, 3. su 명령어의 권한 변경(4750), 4. su 명령어 사용이 필요한 계정을 새로 생성한 그룹에 추가(추가할 계정 요청)\" " >> $action 2>&1
	rpm_libpam_count=`rpm -qa 2>/dev/null | grep '^libpam' | wc -l`
	dnf_libpam_count=`dnf list installed 2>/dev/null | grep -i '^libpam' | wc -l`
	if [ $rpm_libpam_count -gt 0 ] && [ $dnf_libpam_count -gt 0 ]; then
		# !!! pam_rootok.so 설정을 하지 않은 경우 하단의 첫 번째 if 문을 삭제하세요.
		etc_pamd_su_rootokso_count=`grep -vE '^#|^\s#' /etc/pam.d/su | grep 'pam_rootok.so' | wc -l`
		if [ $etc_pamd_su_rootokso_count -gt 0 ]; then
			# !!! pam_wheel.so 설정에 trust 문구를 추가한 경우 하단의 if 문 조건절에 'grep 'trust'를 추가하세요.
			etc_pamd_su_wheelso_count=`grep -vE '^#|^\s#' /etc/pam.d/su | grep 'pam_wheel.so' | wc -l`
			if [ $etc_pamd_su_wheelso_count -eq 0 ]; then
				echo " > U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/pam.d/su 파일에 pam_wheel.so 모듈이 없습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/pam.d/su 파일에 pam_wheel.so 모듈이 없습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/pam.d/su 파일에서 pam_rootok.so 모듈이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/pam.d/su 파일에 pam_wheel.so 모듈이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		su_executables=("/bin/su" "/usr/bin/su")
		if [ `which su 2>/dev/null | wc -l` -gt 0 ]; then
			su_executables[${#su_executables[@]}]=`which su 2>/dev/null`
		fi
		for ((i=0; i<${#su_executables[@]}; i++))
		do
			if [ -f ${su_executables[$i]} ]; then
				su_group_permission=`stat ${su_executables[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
				if [ $su_group_permission -eq 5 ] || [ $su_group_permission -eq 4 ] || [ $su_group_permission -eq 1 ] || [ $su_group_permission -eq 0 ]; then
					su_other_permission=`stat ${su_executables[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
					if [ $su_other_permission -ne 0 ]; then
						echo " > U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${su_executables[$i]} 실행 파일의 다른 사용자(other)에 대한 권한 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${su_executables[$i]} 실행 파일의 다른 사용자(other)에 대한 권한 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-45 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${su_executables[$i]} 실행 파일의 그룹 사용자(group)에 대한 권한 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${su_executables[$i]} 실행 파일의 그룹 사용자(group)에 대한 권한 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		done
	fi
	echo " > U-45 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_46() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-46(중) | 1. 계정관리 > 1.7 패스워드 최소 길이 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"46\", " >> $postdb 2>&1
	echo "  \"id\" : \"46\", " >> $action 2>&1
	echo " 양호 판단 기준 : 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 패스워드 정책 설정파일을 수정하여 패스워드 최소 길이를 8자 이상으로 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"패스워드 정책 설정파일을 수정하여 패스워드 최소 길이를 8자 이상으로 설정\" " >> $action 2>&1
	file_exists_count=0
	minlen_file_exists_count=0
	no_settings_in_minlen_file=0
	input_modules=("pam_pwquality.so" "pam_cracklib.so" "pam_unix.so")
	# /etc/login.defs 파일 내 패스워드 최소 길이 설정 확인함
	if [ -f /etc/login.defs ]; then
		((file_exists_count++))
		((minlen_file_exists_count++))
		etc_logindefs_minlen_count=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_LEN' | awk '{print $2}' | wc -l`
		if [ $etc_logindefs_minlen_count -gt 0 ]; then
		etc_logindefs_minlen_value=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_LEN' | awk '{print $2}'`
			if [ $etc_logindefs_minlen_value -lt 8 ]; then
				echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/login.defs 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/login.defs 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			((no_settings_in_minlen_file++))
		fi
	fi
	# /etc/login.defs 파일 내 패스워드 최소 길이 설정 확인함
	if [ -f /etc/pam.d/system-auth ]; then
		((file_exists_count++))
		for ((c=0; c<${#input_modules[@]}; c++))
		do
			((minlen_file_exists_count++))
			if [ `grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'minlen' | grep -i ${input_modules[$c]} | wc -l` -gt 0 ]; then
				if [ `grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'minlen' | grep -i ${input_modules[$c]} | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,2,1)}'` -lt 8 ]; then
					echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/pam.d/system-auth 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/pam.d/system-auth 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				((no_settings_in_minlen_file++))
			fi
		done
	fi
	# /etc/security/pwquality.conf 파일 내 패스워드 최소 길이와 최소 입력 확인함
	if [ -f /etc/security/pwquality.conf ]; then
		((file_exists_count++))
		# 패스워드 최소 길이 체크
		((minlen_file_exists_count++))
		etc_security_pwqualityconf_minlen_count=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | wc -l`
		if [ $etc_security_pwqualityconf_minlen_count -gt 0 ]; then
			etc_security_pwqualityconf_minlen_value=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,2,1)}'`
			if [ $etc_security_pwqualityconf_minlen_value -lt 8 ]; then
				etc_security_pwqualityconf_minlen_second_value=`grep -vE '^#|^\s#' /etc/security/pwquality.conf | grep -i 'minlen' | awk -F 'minlen' '{gsub(" ", "", $0); print substr($2,3,1)}'`
				if [[ $etc_security_pwqualityconf_minlen_second_value != [0-9] ]]; then
					echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/security/pwquality.conf 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에서 패스워드 최소 길이가 8 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
		return 0
				fi
			else
				if [ -f /etc/pam.d/system-auth ]; then
					etc_pamd_systemauth_module_count=`grep -vE '^#|^\s#' /etc/pam.d/system-auth | grep -i 'pam_pwquality.so' | wc -l`
					if [ $etc_pamd_systemauth_module_count -eq 0 ]; then
						echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/security/pwquality.conf 파일에 최소 길이(minlen)를 8 이상으로 설정하고, /etc/pam.d/system-auth 파일에 pam_pwquality.so 모듈을 추가하지 않았습니다.\" " >> $postdb 2>&1
					return 0
				fi
			fi
		else
			((no_settings_in_minlen_file++))
		fi
	fi
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 패스워드 최소 길이를 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"패스워드 최소 길이를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	elif [ $minlen_file_exists_count -eq $no_settings_in_minlen_file ]; then
		echo " > U-46 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 패스워드 최소 길이를 설정한 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"패스워드 최소 길이를 설정한 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-46 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_47() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-47(중) | 1. 계정관리 > 1.8 패스워드 최대 사용기간 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"47\", " >> $postdb 2>&1
	echo "  \"id\" : \"47\", " >> $action 2>&1
	echo " 양호 판단 기준 : 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 패스워드 정책 설정파일을 수정하여 패스워드 최대 사용기간을 90일(12주)로 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"패스워드 정책 설정파일을 수정하여 패스워드 최대 사용기간을 90일(12주)로 설정\" " >> $action 2>&1
	if [ -f /etc/login.defs ]; then
		etc_logindefs_maxdays_count=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MAX_DAYS' | awk '{print $2}' | wc -l`
		if [ $etc_logindefs_maxdays_count -gt 0 ]; then
			etc_logindefs_maxdays_value=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MAX_DAYS' | awk '{print $2}'`
			if [ $etc_logindefs_maxdays_value -gt 90 ]; then
				echo " > U-47 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/login.defs 파일에 패스워드 최대 사용 기간이 91일 이상으로 설정되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/login.defs 파일에 패스워드 최대 사용 기간이 91일 이상으로 설정되어 있습니다.\" " >> $postdb 2>&1
				return 0
			else
				echo " > U-47 결과 : 양호(Good)" >> $resultfile 2>&1
				echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
				echo "  \"결과상세\" : \"패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있는 경우\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-47 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/login.defs 파일에 패스워드 최대 사용 기간이 설정되어 있지 않습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있는 경우\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-47 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " /etc/login.defs 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/login.defs 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_48() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-48(중) | 1. 계정관리 > 1.9 패스워드 최소 사용기간 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"48\", " >> $postdb 2>&1
	echo "  \"id\" : \"48\", " >> $action 2>&1
	echo " 양호 판단 기준 : 패스워드 최소 사용기간이 1일 이상 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 패스워드 정책 설정파일을 수정하여 패스워드 최소 사용기간을 1일(1주)로 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"패스워드 정책 설정파일을 수정하여 패스워드 최소 사용기간을 1일(1주)로 설정\" " >> $action 2>&1
	if [ -f /etc/login.defs ]; then
		etc_logindefs_mindays_count=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_DAYS' | awk '{print $2}' | wc -l`
		if [ $etc_logindefs_mindays_count -gt 0 ]; then
			etc_logindefs_mindays_value=`grep -vE '^#|^\s#' /etc/login.defs | grep -i 'PASS_MIN_DAYS' | awk '{print $2}'`
			if [ $etc_logindefs_mindays_value -lt 1 ]; then
				echo " > U-48 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/login.defs 파일에 패스워드 최소 사용 기간이 1일 미만으로 설정되어 있습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/login.defs 파일에 패스워드 최소 사용 기간이 1일 미만으로 설정되어 있습니다.\" " >> $postdb 2>&1
				return 0
			else
				echo " > U-48 결과 : 양호(Good)" >> $resultfile 2>&1
				echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
				echo "  \"결과상세\" : \"패스워드 최소 사용기간이 1일 이상 설정되어 있는 경우\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-48 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/login.defs 파일에 패스워드 최소 사용 기간이 설정되어 있지 않습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/login.defs 파일에 패스워드 최소 사용 기간이 설정되어 있지 않습니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-48 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " /etc/login.defs 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/login.defs 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_49() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-49(하) | 1. 계정관리 > 1.10 불필요한 계정 제거 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"49\", " >> $postdb 2>&1
	echo "  \"id\" : \"49\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요한 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	echo " -- 로그를 통한 확인은 수동으로 점검하세요." >> $resultfile 2>&1
	#불필요한 계정에 대한 변경 필요 시 U_49 함수 수정 필요
	echo " -- 불필요한 계정 = daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, gopher, games, ftp, apache, httpd, www-data, mysql, mariadb, postgres, mail, postfix, news, lp, uucp, nuucp" >> $resultfile 2>&1
	echo "     조치방법 : 현재 등록된 계정 현황 확인 후 불필요한 계정 삭제 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"현재 등록된 계정 현황 확인 후 불필요한 계정 삭제\" " >> $action 2>&1
	if [ -f /etc/passwd ]; then
		# !!! 불필요한 계정을 변경할 경우 하단의 grep 명령어를 수정하세요.
		if [ `awk -F : '{print $1}' /etc/passwd | grep -wE 'daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|gopher|games|ftp|apache|httpd|www-data|mysql|mariadb|postgres|mail|postfix|news|lp|uucp|nuucp' | wc -l` -gt 0 ]; then
			echo " > U-49 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 불필요한 계정이 존재합니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"불필요한 계정이 존재합니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-49 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"불필요한 계정이 존재합니다.\" " >> $postdb 2>&1
	return 0
}



U_50() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-50(하) | 1. 계정관리 > 1.11 관리자 그룹에 최소한의 계정 포함 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"50\", " >> $postdb 2>&1
	echo "  \"id\" : \"50\", " >> $action 2>&1
	echo " 양호 판단 기준 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> $resultfile 2>&1
	# 불필요한 계정에 대한 변경 필요 시 U_50 함수 수정 필요
	echo " -- 불필요한 계정 = daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, gopher, games, ftp, apache, httpd, www-data, mysql, mariadb, postgres, mail, postfix, news, lp, uucp, nuucp" >> $resultfile 2>&1
	echo "     조치방법 : 현재 등록된 계정 현황 확인 후 불필요한 계정 삭제 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"현재 등록된 계정 현황 확인 후 불필요한 계정 삭제\" " >> $action 2>&1
	if [ -f /etc/group ]; then
		# !!! 불필요한 계정에 대한 변경은 하단의 grep 명령어를 수정하세요.
		if [ `awk -F : '$1=="root" {gsub(" ", "", $0); print $4}' /etc/group | awk '{gsub(",","\n",$0); print}' | grep -wE 'daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|gopher|games|ftp|apache|httpd|www-data|mysql|mariadb|postgres|mail|postfix|news|lp|uucp|nuucp' | wc -l` -gt 0 ]; then
			echo " > U-50 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 관리자 그룹(root)에 불필요한 계정이 등록되어 있습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"관리자 그룹(root)에 불필요한 계정이 등록되어 있습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-50 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우\" " >> $postdb 2>&1
	return 0
}



U_51() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-51(하) | 1. 계정관리 > 1.12 계정이 존재하지 않는 GID 금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"51\", " >> $postdb 2>&1
	echo "  \"id\" : \"51\", " >> $action 2>&1
	echo " 양호 판단 기준 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우" >> $resultfile 2>&1
	echo " -- 불필요한 그룹 = 그룹에 계정이 존재하지 않는 그룹" >> $resultfile 2>&1
	echo "     조치방법 : 불필요한 그룹이 있을 경우 관리자와 검토하여 제거 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"불필요한 그룹이 있을 경우 관리자와 검토하여 제거\" " >> $action 2>&1
	unnecessary_groups=(`grep -vE '^#|^\s#' /etc/group | awk -F : '$3>=500 && $4==null {print $3}' | uniq`)
	for ((i=0; i<${#unnecessary_groups[@]}; i++))
	do
		if [ `awk -F : '{print $4}' /etc/passwd | uniq | grep ${unnecessary_groups[$i]} | wc -l` -eq 0 ]; then
			echo " > U-51 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 불필요한 그룹이 존재합니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"불필요한 그룹이 존재합니다.\" " >> $postdb 2>&1
			return 0
		fi
	done
	echo " > U-51 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우\" " >> $postdb 2>&1
	return 0
}



U_52() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-52(중) | 1. 계정관리 > 1.13 동일한 UID 금지 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"52\", " >> $postdb 2>&1
	echo "  \"id\" : \"52\", " >> $action 2>&1
	echo " 양호 판단 기준 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 동일한 UID로 설정된 사용자 계정의 UID를 서로 다른 값으로 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"동일한 UID로 설정된 사용자 계정의 UID를 서로 다른 값으로 변경\" " >> $action 2>&1
	if [ -f /etc/passwd ]; then
		if [ `awk -F : '{print $3}' /etc/passwd | sort | uniq -d | wc -l` -gt 0 ]; then
			echo " > U-52 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 동일한 UID로 설정된 사용자 계정이 존재합니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"동일한 UID로 설정된 사용자 계정이 존재합니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-52 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우\" " >> $postdb 2>&1
	return 0
}



U_53() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-53(하) | 1. 계정관리 > 1.14 사용자 shell 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"53\", " >> $postdb 2>&1
	echo "  \"id\" : \"53\", " >> $action 2>&1
	echo " 양호 판단 기준 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있는 경우" >> $resultfile 2>&1
	# 불필요한 계정에 대한 변경 필요 시 U_53 함수 수정 필요
	echo " -- 불필요한 계정 = daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, gopher, games, ftp, apache, httpd, www-data, mysql, mariadb, postgres, mail, postfix, news, lp, uucp, nuucp" >> $resultfile 2>&1
	echo "     조치방법 : 로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin) 쉘 부여 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin) 쉘 부여\" " >> $action 2>&1 
	if [ -f /etc/passwd ]; then
		# !!! 불필요한 계정에 대한 변경은 하단의 grep 명령어를 수정하세요.
		if [ `grep -E '^(daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|gopher|games|ftp|apache|httpd|www-data|mysql|mariadb|postgres|mail|postfix|news|lp|uucp|nuucp):' /etc/passwd | awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" {print}' | wc -l` -gt 0 ]; then
			echo " > U-53 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 로그인이 필요하지 않은 불필요한 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되지 않았습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"로그인이 필요하지 않은 불필요한 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되지 않았습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-53 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_54() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-54(하) | 1. 계정관리 > 1.15 Session Timeout 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"계정관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"54\", " >> $postdb 2>&1
	echo "  \"id\" : \"54\", " >> $action 2>&1
	echo " 양호 판단 기준 : Session Timeout이 600초(10분) 이하로 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 600초(10분) 동안 입력이 없을 경우 접속된 Session을 끊도록 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"600초(10분) 동안 입력이 없을 경우 접속된 Session을 끊도록 설정\" " >> $action 2>&1
	file_exists_count=0 # 세션 타임아웃 설정 파일 존재 시 카운트할 변수
	no_tmout_setting_file=0 # 설정 파일 존재하는데, 세션 타임아웃 설정이 없을 때 카운트할 변수 -> 추후 file_exists_count 변수와 값을 비교하여 동일하면 모든 파일에 세션 타임아웃 설정이 없는 것이므로 취약으로 판단함
	# /etc/profile 파일 내 세션 타임아웃 설정 확인함
	if [ -f /etc/profile ]; then
		((file_exists_count++))
		etc_profile_tmout_count=`grep -vE '^#|^\s#' /etc/profile | grep -i 'TMOUT' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
		if [ $etc_profile_tmout_count -gt 0 ]; then
			etc_profile_tmout_value=`grep -vE '^#|^\s#' /etc/profile | grep -i 'TMOUT' | awk -F = '{gsub(" ", "", $0); print $2}'`
			if [ $etc_profile_tmout_value -gt 600 ]; then
				echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/profile 파일에 세션 타임아웃이 600초 이하로 설정되지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/profile 파일에 세션 타임아웃이 600초 이하로 설정되지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			((no_tmout_setting_file++))
		fi
	fi
	# 사용자 홈 디렉터리 내 .profile 파일에서 세션 타임아웃 설정 확인함
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}'  /etc/passwd | uniq`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		if [ -f ${user_homedirectory_path[$i]}/.profile ]; then
			((file_exists_count++))
			user_homedirectory_profile_tmout_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/.profile | grep -i 'TMOUT' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
			if [ $user_homedirectory_profile_tmout_count -gt 0 ]; then
				user_homedirectory_profile_tmout_value=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/.profile | grep -i 'TMOUT' | awk -F = '{gsub(" ", "", $0); print $2}'`
				if [ $user_homedirectory_profile_tmout_value -gt 600 ]; then
					echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${user_homedirectory_path[$i]}/.profile 파일에 세션 타임아웃이 600초 이하로 설정되지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/.profile 파일에 세션 타임아웃이 600초 이하로 설정되지 않았습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				((no_tmout_setting_file++))
			fi
		fi
	done
	# /etc/csh.login 파일 내 세션 타임아웃 설정 확인함
	if [ -f /etc/csh.login ]; then
		((file_exists_count++))
		etc_cshlogin_tmout_count=`grep -vE '^#|^\s#' /etc/csh.login | grep -i 'set' | grep -i 'autologout' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
		if [ $etc_cshlogin_tmout_count -gt 0 ]; then
			etc_cshlogin_tmout_value=`grep -vE '^#|^\s#' /etc/csh.login | grep -i 'set' | grep -i 'autologout' | awk -F = '{gsub(" ", "", $0); print $2}'`
			if [ $etc_cshlogin_tmout_value -gt 10 ]; then
				echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/csh.login 파일에 세션 타임아웃이 10분 이하로 설정되지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/csh.login 파일에 세션 타임아웃이 10분 이하로 설정되지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			((no_tmout_setting_file++))
		fi
	fi
	# /etc/csh.cshrc 파일 내 세션 타임아웃 설정 확인함
	if [ -f /etc/csh.cshrc ]; then
		((file_exists_count++))
		etc_cshrc_tmout_count=`grep -vE '^#|^\s#' /etc/csh.cshrc | grep -i 'set' | grep -i 'autologout' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
		if [ $etc_cshrc_tmout_count -gt 10 ]; then
			etc_cshrc_tmout_value=`grep -vE '^#|^\s#' /etc/csh.cshrc | grep -i 'set' | grep -i 'autologout' | awk -F = '{gsub(" ", "", $0); print $2}'`
			if [ $etc_cshrc_tmout_value -gt 10 ]; then
				echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/csh.cshrc 파일에 세션 타임아웃이 10분 이하로 설정되지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/csh.cshrc 파일에 세션 타임아웃이 10분 이하로 설정되지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			((no_tmout_setting_file++))
		fi
	fi
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 세션 타임아웃을 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"세션 타임아웃을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	elif [ $file_exists_count -eq $no_tmout_setting_file ]; then
		echo " > U-54 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 세션 타임아웃을 설정한 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"세션 타임아웃을 설정한 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-54 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"Session Timeout이 600초(10분) 이하로 설정되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_55() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-55(하) | 2. 파일 및 디렉토리 관리 > 2.15 hosts.lpd 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"55\", " >> $postdb 2>&1
	echo "  \"id\" : \"55\", " >> $action 2>&1
	echo " 양호 판단 기준 : hosts.lpd 파일이 삭제되어 있거나 불가피하게 hosts.lpd 파일을 사용할 시 파일의 소유자가 root이고 권한이 600인 경우" >> $resultfile 2>&1
	echo "     조치방법 : hosts.lpd 파일을 삭제하거나 hosts.lpd 파일의 퍼미션을 확인하여 퍼미션 600, 파일 소유자를 root로 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"hosts.lpd 파일을 삭제하거나 hosts.lpd 파일의 퍼미션을 확인하여 퍼미션 600, 파일 소유자를 root로 변경\" " >> $action 2>&1
	if [ -f /etc/hosts.lpd ]; then
		etc_hostslpd_owner_name=`ls -l /etc/hosts.lpd | awk '{print $3}'`
		if [[ $etc_hostslpd_owner_name =~ root ]]; then
			etc_hostslpd_permission=`stat /etc/hosts.lpd | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_hostslpd_permission -eq 600 ]; then
				echo " > U-55 결과 : 양호(Good)" >> $resultfile 2>&1
				echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
				echo "  \"결과상세\" : \"hosts.lpd 파일이 삭제되어 있거나 불가피하게 hosts.lpd 파일을 사용할 시 파일의 소유자가 root이고 권한이 600인 경우\" " >> $postdb 2>&1
				return 0
			else
				echo " > U-55 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/hosts.lpd 파일의 권한이 600이 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/hosts.lpd 파일의 권한이 600이 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-55 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/hosts.lpd 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/hosts.lpd 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-55 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"hosts.lpd 파일이 삭제되어 있거나 불가피하게 hosts.lpd 파일을 사용할 시 파일의 소유자가 root이고 권한이 600인 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_56() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-56(중) | 2. 파일 및 디렉토리 관리 > 2.17 UMASK 설정 관리 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리 \", " >> $postdb 2>&1
	echo "  \"id\" : \"56\", " >> $postdb 2>&1
	echo "  \"id\" : \"56\", " >> $action 2>&1
	echo " 양호 판단 기준 : UMASK 값이 022 이상으로 설정된 경우" >> $resultfile 2>&1
	echo "     조치방법 : 설정파일에 UMASK 값을 “022”로 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"설정파일에 UMASK 값을 “022”로 설정\" " >> $action 2>&1
	umaks_value=`umask`
	if [ ${umaks_value:2:1} -lt 2 ]; then
		echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
		return 0
	elif [ ${umaks_value:3:1} -lt 2 ]; then
		echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
		return 0
	fi
	# /etc/profile 파일 내 umask 설정 확인함
	etc_profile_umask_count=`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | grep '=' | wc -l` # 설정 파일에 <umask=값> 형식으로 umask 값이 설정된 경우
	etc_profile_umask_count2=`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l` # 설정 파일에 <umask 값> 형식으로 umask 값이 설정된 경우
	if [ -f /etc/profile ]; then
		if [ $etc_profile_umask_count -gt 0 ]; then
			umaks_value=(`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk -F = '{gsub(" ", "", $0); print $2}'`)
			for ((i=0; i<${#umaks_value[@]}; i++))
			do
				if [ ${#umaks_value[$i]} -eq 2 ]; then
					if [ ${umaks_value[$i]:0:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 4 ]; then
					if [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:3:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 3 ]; then
					if [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 1 ]; then
					echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
					return 0
				else
					echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		elif [ $etc_profile_umask_count2 -gt 0 ]; then
			umaks_value=(`grep -vE '^#|^\s#' /etc/profile | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
			for ((i=0; i<${#umaks_value[@]}; i++))
			do
				if [ ${#umaks_value[$i]} -eq 2 ]; then
					if [ ${umaks_value[$i]:0:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 4 ]; then
					if [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:3:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 3 ]; then
					if [ ${umaks_value[$i]:1:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					elif [ ${umaks_value[$i]:2:1} -lt 2 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/profile 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					fi
				elif [ ${#umaks_value[$i]} -eq 1 ]; then
					echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/profile 파일에 umask 값이 0022 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
					return 0
				else
					echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/profile 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	fi
	# /etc/bashrc, /etc/csh.login, /etc/csh.cshrc 파일 내 umask 설정 확인함
	umask_settings_files=("/etc/bashrc" "/etc/csh.login" "/etc/csh.cshrc")
	for ((i=0; i<${#umask_settings_files[@]}; i++))
	do
		if [ -f ${umask_settings_files[$i]} ]; then
			file_umask_count=`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l`
			if [ $file_umask_count -gt 0 ]; then
				umaks_value=(`grep -vE '^#|^\s#' ${umask_settings_files[$i]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
				for ((j=0; j<${#umaks_value[@]}; j++))
				do
					if [ ${#umaks_value[$j]} -eq 2 ]; then
						if [ ${umaks_value[$j]:0:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						elif [ ${umaks_value[$j]:1:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					elif [ ${#umaks_value[$j]} -eq 4 ]; then
						if [ ${umaks_value[$j]:2:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						elif [ ${umaks_value[$j]:3:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					elif [ ${#umaks_value[$j]} -eq 3 ]; then
						if [ ${umaks_value[$j]:1:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						elif [ ${umaks_value[$j]:2:1} -lt 2 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					elif [ ${#umaks_value[$j]} -eq 1 ]; then
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${umask_settings_files[$i]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
						return 0
					else
						echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${umask_settings_files[$i]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${umask_settings_files[$i]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다.\" " >> $postdb 2>&1
						return 0
					fi
				done
			fi
		fi
	done
	# 사용자 홈 디렉터리 내 설정 파일에서 umask 설정 확인함
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	umask_settings_files=(".cshrc" ".profile" ".login" ".bashrc" ".kshrc")
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		for ((j=0; j<${#umask_settings_files[@]}; j++))
		do
			if [ -f ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} ]; then
				user_homedirectory_setting_umask_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}' | wc -l`
				if [ $user_homedirectory_setting_umask_count -gt 0 ]; then
					umaks_value=(`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} | grep -i 'umask' | grep -vE 'if|\`' | awk '{print $2}'`)
					for ((k=0; k<${#umaks_value[@]}; k++))
					do
						if [ ${#umaks_value[$k]} -eq 2 ]; then
							if [ ${umaks_value[$k]:0:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							elif [ ${umaks_value[$k]:1:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						elif [ ${#umaks_value[$k]} -eq 4 ]; then
							if [ ${umaks_value[$k]:2:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							elif [ ${umaks_value[$k]:3:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						elif [ ${#umaks_value[$k]} -eq 3 ]; then
							if [ ${umaks_value[$k]:1:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							elif [ ${umaks_value[$k]:2:1} -lt 2 ]; then
								echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						elif [ ${#umaks_value[$k]} -eq 1 ]; then
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 umask 값이 0022 이상으로 설정되지 않았습니다.\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-56 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${user_homedirectory_path[$i]}/${umask_settings_files[$j]} 파일에 설정된 umask 값이 보안 설정에 부합하지 않습니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	done
	echo " > U-56 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"UMASK 값이 022 이상으로 설정된 경우\" " >> $postdb 2>&1
	return 0
}

U_57() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-57(중) | 2. 파일 및 디렉토리 관리 > 2.18 홈디렉토리 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"57\", " >> $postdb 2>&1
	echo "  \"id\" : \"57\", " >> $action 2>&1
	echo " 양호 판단 기준 : 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우" >> $resultfile 2>&1
	echo "     조치방법 : 사용자별 홈 디렉터리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거(“/etc/passwd” 파일에서 홈 디렉터리 확인, 사용자 홈 디렉터리 외 개별적으로 만들어 사용하는 사용자 디렉터리 존재 여부 확인하여 점검) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"사용자별 홈 디렉터리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거(“/etc/passwd” 파일에서 홈 디렉터리 확인, 사용자 홈 디렉터리 외 개별적으로 만들어 사용하는 사용자 디렉터리 존재 여부 확인하여 점검)\" " >> $action 2>&1
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		if [ -d ${user_homedirectory_path[$i]} ]; then
			homedirectory_owner_name=`ls -ld ${user_homedirectory_path[$i]} | awk '{print $3}'`
			if [[ $homedirectory_owner_name =~ ${user_homedirectory_owner_name[$i]} ]]; then
				homedirectory_other_permission=`stat ${user_homedirectory_path[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
				if [ $homedirectory_other_permission -eq 7 ] || [ $homedirectory_other_permission -eq 6 ] || [ $homedirectory_other_permission -eq 3 ] || [ $homedirectory_other_permission -eq 2 ]; then
					echo " > U-57 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${user_homedirectory_path[$i]} 홈 디렉터리에 다른 사용자(other)의 쓰기 권한이 부여되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${user_homedirectory_path[$i]} 홈 디렉터리에 다른 사용자(other)의 쓰기 권한이 부여되어 있습니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-57 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${user_homedirectory_path[$i]} 홈 디렉터리의 소유자가 ${user_homedirectory_owner_name[$i]}이(가) 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${user_homedirectory_path[$i]} 홈 디렉터리에 다른 사용자(other)의 쓰기 권한이 부여되어 있습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	echo " > U-57 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우\" " >> $postdb 2>&1
	return 0
}

U_58() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-58(중) | 2. 파일 및 디렉토리 관리 > 2.19 홈디렉토리로 지정한 디렉토리의 존재 관리 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"58\", " >> $postdb 2>&1
	echo "  \"id\" : \"58\", " >> $action 2>&1
	echo " 양호 판단 기준 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 홈 디렉터리가 존재하지 않는 계정에 홈 디렉터리 설정 또는, 계정 삭제 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"홈 디렉터리가 존재하지 않는 계정에 홈 디렉터리 설정 또는, 계정 삭제\" " >> $action 2>&1
	homedirectory_null_count=`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6==null' /etc/passwd | wc -l`
	if [ $homedirectory_null_count -gt 0 ]; then
		echo " > U-58 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 홈 디렉터리가 존재하지 않는 계정이 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"홈 디렉터리가 존재하지 않는 계정이 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		homedirectory_slash_count=`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $1!="root" && $6=="/"' /etc/passwd | wc -l`
		if [ $homedirectory_slash_count -gt 0 ]; then
			echo " > U-58 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " 관리자 계정(root)이 아닌데 홈 디렉터리가 '/'로 설정된 계정이 있습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"관리자 계정(root)이 아닌데 홈 디렉터리가 '/'로 설정된 계정이 있습니다.\" " >> $postdb 2>&1
			return 0
		else
			echo " > U-58 결과 : 양호(Good)" >> $resultfile 2>&1
			echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
			echo "  \"결과상세\" : \"양호 판단 기준 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우\" " >> $postdb 2>&1
			return 0
		fi
	fi
}

U_59() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-59(하) | 2. 파일 및 디렉토리 관리 > 2.20 숨겨진 파일 및 디렉토리 검색 및 제거 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"파일 및 디렉토리 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"59\", " >> $postdb 2>&1
	echo "  \"id\" : \"59\", " >> $action 2>&1
	echo " 양호 판단 기준 : 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 삭제한 경우" >> $resultfile 2>&1
	echo "     조치방법 : ls –al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 삭제함 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"ls –al 명령어로 숨겨진 파일 존재 파악 후 불법적이거나 의심스러운 파일을 삭제함\" " >> $action 2>&1
	if [ `find / -name '.*' -type f 2>/dev/null | wc -l` -gt 0 ]; then
		echo " > U-59 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 숨겨진 파일이 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"숨겨진 파일이 있습니다.\" " >> $postdb 2>&1
		return 0
	elif [ `find / -name '.*' -type d 2>/dev/null | wc -l` -gt 0 ]; then
		echo " > U-59 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " 숨겨진 디렉터리가 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"숨겨진 디렉터리가 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-59 결과 : 양호(Good)" >> $resultfile 2>&1$resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 삭제한 경우\" " >> $postdb 2>&1
		return 0
	fi
}

U_60() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-60(중) | 3. 서비스 관리 > 3.24 ssh 원격접속 허용 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"60\", " >> $postdb 2>&1
	echo "  \"id\" : \"60\", " >> $action 2>&1
	echo " 양호 판단 기준 : 원격 접속 시 SSH 프로토콜을 사용하는 경우" >> $resultfile 2>&1
	echo " -- ssh, telnet이 동시에 설치되어 있는 경우 취약한 것으로 평가됨" >> $resultfile 2>&1
	echo "     조치방법 : Telnet, FTP 등 안전하지 않은 서비스 사용을 중지하고, SSH 설치 및 사용 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Telnet, FTP 등 안전하지 않은 서비스 사용을 중지하고, SSH 설치 및 사용\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		telent_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $telent_port_count -gt 0 ]; then
			telent_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#telent_port[@]}; i++))
			do
				netstat_telnet_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${telent_port[$i]}" | wc -l`
				if [ $netstat_telnet_count -gt 0 ]; then
					echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " Telnet 서비스가 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"Telnet 서비스가 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
		ftp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $ftp_port_count -gt 0 ]; then
			ftp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#ftp_port[@]}; i++))
			do
				netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$i]}" | wc -l`
				if [ $netstat_ftp_count -gt 0 ]; then
					echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	fi
	find_vsftpdconf_count=`find / -name 'vsftpd.conf' -type f 2>/dev/null | wc -l`
	if [ $find_vsftpdconf_count -gt 0 ]; then
		vsftpdconf_files=(`find / -name 'vsftpd.conf' -type f 2>/dev/null`)
		for ((i=0; i<${#vsftpdconf_files[@]}; i++))
		do
			if [ -f ${vsftpdconf_files[$i]} ]; then
				vsftpdconf_file_port_count=`grep -vE '^#|^\s#' ${vsftpdconf_files[$i]} | grep 'listen_port' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
				if [ $vsftpdconf_file_port_count -gt 0 ]; then
					telent_port=(`grep -vE '^#|^\s#' ${vsftpdconf_files[$i]} | grep 'listen_port' | awk -F = '{gsub(" ", "", $0); print $2}'`)
					for ((j=0; j<${#telent_port[@]}; j++))
					do
						if [ `netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${telent_port[$j]}" | wc -l` -gt 0 ]; then
							echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	fi
	find_proftpdconf_count=`find / -name 'proftpd.conf' -type f 2>/dev/null | wc -l`
	if [ $find_proftpdconf_count -gt 0 ]; then
		proftpdconf_files=(`find / -name 'proftpd.conf' -type f 2>/dev/null`)
		for ((i=0; i<${#proftpdconf_files[@]}; i++))
		do
			if [ -f ${proftpdconf_files[$i]} ]; then
				if [ `grep -vE '^#|^\s#' ${proftpdconf_files[$i]} | grep 'Port' | awk '{print $2}' | wc -l` -gt 0 ]; then
					telent_port=(`grep -vE '^#|^\s#' ${proftpdconf_files[$i]} | grep 'Port' | awk '{print $2}'`)
					for ((j=0; j<${#telent_port[@]}; j++))
					do
						if [ `netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${telent_port[$j]}" | wc -l` -gt 0 ]; then
							echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	fi
	ps_telnet_count=`ps -ef | grep -i 'telnet' | grep -v 'grep' | wc -l`
	if [ $ps_telnet_count -gt 0 ]; then
		echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " Telnet 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"Telnet 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	fi
	ps_ftp_count=`ps -ef | grep -i 'ftp' | grep -v 'grep' | wc -l`
	if [ $ps_ftp_count -gt 0 ]; then
		echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	fi
	find_sshdconfig_count=`find / -name 'sshd_config' -type f 2>/dev/null | wc -l`
	if [ $find_sshdconfig_count -gt 0 ]; then
		sshdconfig_files=(`find / -name 'sshd_config' -type f 2>/dev/null`)
		for ((i=0; i<${#sshdconfig_files[@]}; i++))
		do
			if [ -f ${sshdconfig_files[$i]} ]; then
				if [ `grep -vE '^#|^\s#' ${sshdconfig_files[$i]} | grep -i 'Port' | awk '{print $2}' | wc -l` -gt 0 ]; then
					ssh_port=(`grep -vE '^#|^\s#' ${sshdconfig_files[$i]} | grep -i 'Port' | awk '{print $2}'`)
					for ((j=0; j<${#ssh_port[@]}; j++))
					do
						netstat_ssh_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ssh_port[$j]}" | wc -l`
						if [ $netstat_ssh_count -eq 0 ]; then
							echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " SSH 서비스가 비활성화 상태입니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"SSH 서비스가 비활성화 상태입니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	fi
	ps_ssh_count=`ps -ef | grep -i 'sshd' | grep -v 'grep' | wc -l`
	if [ $ps_ssh_count -eq 0 ]; then
		echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " SSH 서비스가 비활성화 상태입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"SSH 서비스가 비활성화 상태입니다.\" " >> $postdb 2>&1
		return 0
	fi
	rpm_ssh_count=`rpm -qa 2>/dev/null | grep '^openssh' | wc -l`
	dnf_ssh_count=`dnf list installed 2>/dev/null | grep -i '^openssh' | wc -l`
	rpm_telnet_count=`rpm -qa 2>/dev/null | grep '^telnet' | wc -l`
	dnf_telnet_count=`dnf list installed 2>/dev/null | grep -i '^telnet' | wc -l`
	if [ $rpm_ssh_count -gt 0 ] && [ $dnf_ssh_count -gt 0 ] && [ $rpm_telnet_count -gt 0 ] && [ $dnf_telnet_count -gt 0 ]; then
		echo " > U-60 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " SSH 서비스와 Telnet 서비스가 동시에 설치되어 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"SSH 서비스와 Telnet 서비스가 동시에 설치되어 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-60 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"원격 접속 시 SSH 프로토콜을 사용하는 경우\" " >> $postdb 2>&1
		return 0
	fi
}

U_61() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-61(하) | 3. 서비스 관리 > 3.25 ftp 서비스 확인 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"61\", " >> $postdb 2>&1
	echo "  \"id\" : \"61\", " >> $action 2>&1
	echo " 양호 판단 기준 : FTP 서비스가 비활성화 되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : FTP 서비스 중지 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"FTP 서비스 중지\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		ftp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $ftp_port_count -gt 0 ]; then
			ftp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#ftp_port[@]}; i++))
			do
				netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$i]}" | wc -l`
				if [ $netstat_ftp_count -gt 0 ]; then
					echo " > U-61 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	fi
	find_vsftpdconf_count=`find / -name 'vsftpd.conf' -type f 2>/dev/null | wc -l`
	if [ $find_vsftpdconf_count -gt 0 ]; then
		vsftpdconf_files=(`find / -name 'vsftpd.conf' -type f 2>/dev/null`)
		for ((i=0; i<${#vsftpdconf_files[@]}; i++))
		do
			if [ -f ${vsftpdconf_files[$i]} ]; then
				vsftpdconf_file_port_count=`grep -vE '^#|^\s#' ${vsftpdconf_files[$i]} | grep 'listen_port' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
				if [ $vsftpdconf_file_port_count -gt 0 ]; then
					ftp_port=(`grep -vE '^#|^\s#' ${vsftpdconf_files[$i]} | grep 'listen_port' | awk -F = '{gsub(" ", "", $0); print $2}'`)
					for ((j=0; j<${#ftp_port[@]}; j++))
					do
						netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$j]}" | wc -l`
						if [ $netstat_ftp_count -gt 0 ]; then
							echo " > U-61 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	fi
	find_proftpdconf_count=`find / -name 'proftpd.conf' -type f 2>/dev/null | wc -l`
	if [ $find_proftpdconf_count -gt 0 ]; then
		proftpdconf_files=(`find / -name 'proftpd.conf' -type f 2>/dev/null`)
		for ((i=0; i<${#proftpdconf_files[@]}; i++))
		do
			if [ -f ${proftpdconf_files[$i]} ]; then
				proftpdconf_file_port_count=`grep -vE '^#|^\s#' ${proftpdconf_files[$i]} | grep 'Port' | awk '{print $2}' | wc -l`
				if [ $proftpdconf_file_port_count -gt 0 ]; then
					ftp_port=(`grep -vE '^#|^\s#' ${proftpdconf_files[$i]} | grep 'Port' | awk '{print $2}'`)
					for ((j=0; j<${#ftp_port[@]}; j++))
					do
						netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$j]}" | wc -l`
						if [ $netstat_ftp_count -gt 0 ]; then
							echo " > U-61 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
							return 0
						fi
					done
				fi
			fi
		done
	fi
	ps_ftp_count=`ps -ef | grep -iE 'ftp|vsftpd|proftp' | grep -v 'grep' | wc -l`
	if [ $ps_ftp_count -gt 0 ]; then
		echo " > U-61 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 서비스가 실행 중입니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 서비스가 실행 중입니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-61 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"FTP 서비스가 비활성화 되어 있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}

U_62() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-62(중) | 3. 서비스 관리 > 3.26 ftp 계정 shell 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"62\", " >> $postdb 2>&1
	echo "  \"id\" : \"62\", " >> $action 2>&1
	echo " 양호 판단 기준 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : ftp 계정에 /bin/false 쉘 부여 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"ftp 계정에 /bin/false 쉘 부여\" " >> $action 2>&1
	if [ `awk -F : '$1=="ftp" && $7=="/bin/false"' /etc/passwd | wc -l` -gt 0 ]; then
		echo " > U-62 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"ftp 계정에 /bin/false 쉘이 부여되어 있는 경우\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-62 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 계정에 /bin/false 쉘이 부여되어 있지 않습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 계정에 /bin/false 쉘이 부여되어 있지 않습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_63() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-63(하) | 3. 서비스 관리 > 3.27 ftpusers 파일 소유자 및 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"63\", " >> $postdb 2>&1
	echo "  \"id\" : \"63\", " >> $action 2>&1
	echo " 양호 판단 기준 : ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우" >> $resultfile 2>&1
	echo "     조치방법 : FTP 접근제어 파일의 소유자 및 권한 변경 (소유자 root, 권한 640 이하) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"FTP 접근제어 파일의 소유자 및 권한 변경 (소유자 root, 권한 640 이하)\" " >> $action 2>&1
	file_exists_count=0
	ftpusers_files=("/etc/ftpusers" "/etc/pure-ftpd/ftpusers" "/etc/wu-ftpd/ftpusers" "/etc/vsftpd/ftpusers" "/etc/proftpd/ftpusers" "/etc/ftpd/ftpusers" "/etc/vsftpd.ftpusers" "/etc/vsftpd.user_list" "/etc/vsftpd/user_list")
	for ((i=0; i<${#ftpusers_files[@]}; i++))
	do
		if [ -f ${ftpusers_files[$i]} ]; then
			((file_exists_count++))
			ftpusers_file_owner_name=`ls -l ${ftpusers_files[$i]} | awk '{print $3}'`
			if [[ $ftpusers_file_owner_name =~ root ]]; then
				ftpusers_file_permission=`stat ${ftpusers_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
				if [ $ftpusers_file_permission -le 640 ]; then
					ftpusers_file_owner_permission=`stat ${ftpusers_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
					if [ $ftpusers_file_owner_permission -eq 6 ] || [ $ftpusers_file_owner_permission -eq 4 ] || [ $ftpusers_file_owner_permission -eq 2 ] || [ $ftpusers_file_owner_permission -eq 0 ]; then
						ftpusers_file_group_permission=`stat ${ftpusers_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
						if [ $ftpusers_file_group_permission -eq 4 ] || [ $ftpusers_file_group_permission -eq 0 ]; then
							ftpusers_file_other_permission=`stat ${ftpusers_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
							if [ $ftpusers_file_other_permission -ne 0 ]; then
								echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${ftpusers_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${ftpusers_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${ftpusers_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${ftpusers_files[$i]} 파일의 권한이 640보다 큽니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일의 권한이 640보다 큽니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${ftpusers_files[$i]} 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	if [ $file_exists_count -eq 0 ]; then
		echo " > U-63 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 접근제어 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 접근제어 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-63 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_64() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-64(중) | 3. 서비스 관리 > 3.28 ftpusers 파일 설정(FTP 서비스 root 계정 접근제한) "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"64\", " >> $postdb 2>&1
	echo "  \"id\" : \"64\", " >> $action 2>&1
	echo " 양호 판단 기준 : FTP 서비스가 비활성화 되어 있거나, 활성화 시 root 계정 접속을 차단한 경우" >> $resultfile 2>&1
	echo "     조치방법 : FTP 접속 시 root 계정으로 직접 접속 할 수 없도록 설정파일 수정(접속 차단 계정을 등록하는 ftpusers 파일에 root 계정 추가) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"FTP 접속 시 root 계정으로 직접 접속 할 수 없도록 설정파일 수정(접속 차단 계정을 등록하는 ftpusers 파일에 root 계정 추가)\" " >> $action 2>&1
	ftpusers_files=("/etc/ftpusers" "/etc/ftpd/ftpusers" "/etc/proftpd.conf" "/etc/vsftp/ftpusers" "/etc/vsftp/user_list" "/etc/vsftpd.ftpusers" "/etc/vsftpd.user_list")
	ftp_running_count=0 # ftp 서비스 실행 중일 때 카운트
	ftpusers_file_exists_count=0 # ftpusers 파일 존재 시 카운트
	if [ -f /etc/services ]; then
		ftp_port_count=`grep -vE '^#|^\s#' /etc/services | awk -F " " 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $ftp_port_count -gt 0 ]; then
			ftp_port=(`grep -vE '^#|^\s#' /etc/services | awk -F " " 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#ftp_port[@]}; i++))
			do
				netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$i]}" | wc -l`
				if [ $netstat_ftp_count -gt 0 ]; then
					((ftp_running_count++))
					for ((j=0; j<${#ftpusers_files[@]}; j++))
					do
						if [ -f ${ftpusers_files[$j]} ]; then
							((ftpusers_file_exists_count++))
							if [[ ${ftpusers_files[$j]} =~ /etc/proftpd.conf ]]; then
								etc_proftpdconf_rootlogin_on_count=`grep -vE '^#|^\s#' ${ftpusers_files[$j]} | grep -i 'RootLogin' | grep -i 'on' | wc -l`
								if [ $etc_proftpdconf_rootlogin_on_count -gt 0 ]; then
									echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " ${ftpusers_files[$j]} 파일에 'RootLogin on' 설정이 있습니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"${ftpusers_files[$j]} 파일에 'RootLogin on' 설정이 있습니다.\" " >> $postdb 2>&1
									return 0
								fi
							else
								ftp_root_count=`grep -vE '^#|^\s#' ${ftpusers_files[$j]} | grep -w 'root' | wc -l`
								if [ $ftp_root_count -eq 0 ]; then
									echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
									echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
									echo " ${ftpusers_files[$j]} 파일에 'root' 계정이 없습니다." >> $resultfile 2>&1
									echo "  \"결과상세\" : \"${ftpusers_files[$j]} 파일에 'root' 계정이 없습니다.\" " >> $postdb 2>&1
									return 0
								fi
							fi
						fi
					done
				fi
			done
		fi
	fi
	if [ $ftp_running_count -gt 0 ] && [ $ftpusers_file_exists_count -eq 0 ]; then
		echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 서비스를 사용하고, 'root' 계정의 접근을 제한할 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 서비스를 사용하고, 'root' 계정의 접근을 제한할 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
	ftp_running_count=0 # ftp 서비스 실행 중일 때 카운트
	ftpusers_file_exists_count=0 # ftpusers 파일 존재 시 카운트
	ps_ftp_count=`ps -ef | grep -iE 'ftp|vsftpd|proftp' | grep -v 'grep' | wc -l`
	if [ $ps_ftp_count -gt 0 ]; then
		((ftp_running_count++))
		for ((i=0; i<${#ftpusers_files[@]}; i++))
		do
			if [ -f ${ftpusers_files[$i]} ]; then
				((ftpusers_file_exists_count++))
				if [[ ${ftpusers_files[$i]} =~ /etc/proftpd.conf ]]; then
					etc_proftpdconf_rootlogin_on_count=`grep -vE '^#|^\s#' ${ftpusers_files[$i]} | grep -i 'RootLogin' | grep -i 'on' | wc -l`
					if [ $etc_proftpdconf_rootlogin_on_count -gt 0 ]; then
						echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${ftpusers_files[$i]} 파일에 'RootLogin on' 설정이 있습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일에 'RootLogin on' 설정이 있습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					ftp_root_count=`grep -vE '^#|^\s#' ${ftpusers_files[$i]} | grep -w 'root' | wc -l`
					if [ $ftp_root_count -eq 0 ]; then
						echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${ftpusers_files[$i]} 파일에 'root' 계정이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${ftpusers_files[$i]} 파일에 'root' 계정이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			fi
		done
	fi
	if [ $ftp_running_count -gt 0 ] && [ $ftpusers_file_exists_count -eq 0 ]; then
		echo " > U-64 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " ftp 서비스를 사용하고, 'root' 계정의 접근을 제한할 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"ftp 서비스를 사용하고, 'root' 계정의 접근을 제한할 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
	echo " > U-64 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"FTP 서비스가 비활성화 되어 있거나, 활성화 시 root 계정 접속을 차단한 경우\" " >> $postdb 2>&1
	return 0
}



U_65() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-65(중) | 3. 서비스 관리 > 3.29 at 서비스 권한 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"65\", " >> $postdb 2>&1
	echo "  \"id\" : \"65\", " >> $action 2>&1
	echo " 양호 판단 기준 : at 명령어 일반 사용자 금지 및 at 관련 파일 640 이하인 경우" >> $resultfile 2>&1
	echo "     조치방법 : crontab 명령어 750 이하, cron 관련 파일 소유자 및 권한 변경(소유자 root, 권한 640 이하) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"crontab 명령어 750 이하, cron 관련 파일 소유자 및 권한 변경(소유자 root, 권한 640 이하)\" " >> $action 2>&1
	user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	path_setting_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
	path=(`echo $PATH | awk -F : '{for (i=1; i<=NF; i++) {print $i}}'`)
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		for ((j=0; j<${#path_setting_files[@]}; j++))
		do
			if [ -f ${user_homedirectory_path[$i]}/${path_setting_files[$j]} ]; then
				user_homedirectory_path_count=`grep -i 'path' ${user_homedirectory_path[$i]}/${path_setting_files[$j]} | wc -l`
				if [ $user_homedirectory_path_count -gt 0 ]; then
					path_setting_file_in_path=(`grep -i 'PATH' ${user_homedirectory_path[$i]}/${path_setting_files[$j]} | awk -F \" '{print $2}' | awk -F : '{for (l=1;l<=NF;l++) {print $l}}'`)
					for ((k=0; k<${#path_setting_file_in_path[@]}; k++))
					do
						if [[ ${path_setting_file_in_path[$k]} != \$PATH ]]; then
							if [[ ${path_setting_file_in_path[$k]} == \$HOME* ]]; then
								path_setting_file_in_path[$k]=$(echo ${path_setting_file_in_path[$k]} | awk -v u65_awk=${user_homedirectory_path[i]} '{gsub("\\$HOME",u65_awk,$0)} 1')
							fi
							path[${#path[@]}]=${path_setting_file_in_path[$k]}
						fi
					done
				fi
			fi
		done
	done
	for ((i=0; i<${#path[@]}; i++))
	do
		if [ -f ${path[$i]}/at ]; then
			at_file_group_permission=`stat ${path[$i]}/at | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
			if [ $at_file_group_permission -eq 5 ] || [ $at_file_group_permission -eq 4 ] || [ $at_file_group_permission -eq 1 ] || [ $at_file_group_permission -eq 0 ]; then
				at_file_other_permission=`stat ${path[$i]}/at | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
				if [ $at_file_other_permission -ne 0 ]; then
					echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${path[$i]}/at 실행 파일이 다른 사용자(other)에 의해 실행이 가능합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${path[$i]}/at 실행 파일이 다른 사용자(other)에 의해 실행이 가능합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${path[$i]}/at 실행 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${path[$i]}/at 실행 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	at_access_control_files=("/etc/at.allow" "/etc/at.deny")
	for ((i=0; i<${#at_access_control_files[@]}; i++))
	do
		if [ -f ${at_access_control_files[$i]} ]; then
			at_file_owner_name=`ls -l ${at_access_control_files[$i]} | awk '{print $3}'`
			if [[ $at_file_owner_name =~ root ]]; then
				at_file_permission=`stat ${at_access_control_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
				if [ $at_file_permission -le 640 ]; then
					at_file_owner_permission=`stat ${at_access_control_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
					if [ $at_file_owner_permission -eq 6 ] || [ $at_file_owner_permission -eq 4 ] || [ $at_file_owner_permission -eq 2 ] || [ $at_file_owner_permission -eq 0 ]; then
						at_file_group_permission=`stat ${at_access_control_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
						if [ $at_file_group_permission -eq 4 ] || $at_file_owner_permission -eq 0 ]; then
							at_file_other_permission=`stat ${at_access_control_files[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
							if [ $at_file_other_permission -ne 0 ]; then
								echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${at_access_control_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${at_access_control_files[$i]} 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
								return 0
							fi
						else
							echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ${at_access_control_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"${at_access_control_files[$i]} 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${at_access_control_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${at_access_control_files[$i]} 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${at_access_control_files[$i]} 파일의 권한이 640보다 큽니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${at_access_control_files[$i]} 파일의 권한이 640보다 큽니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-65 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ${at_access_control_files[$i]} 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"${at_access_control_files[$i]} 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
	done
	echo " > U-65 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"at 명령어 일반 사용자 금지 및 at 관련 파일 640 이하인 경우\" " >> $postdb 2>&1
	return 0
}



U_66() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-66(중) | 3. 서비스 관리 > 3.30 SNMP 서비스 구동 점검 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"66\", " >> $postdb 2>&1
	echo "  \"id\" : \"66\", " >> $action 2>&1
	echo " 양호 판단 기준 : SNMP 서비스를 사용하지 않는 경우" >> $resultfile 2>&1
	echo "     조치방법 : SNMP 서비스를 사용하지 않는 경우 서비스 중지 후 시작 스크립트 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"SNMP 서비스를 사용하지 않는 경우 서비스 중지 후 시작 스크립트 변경\" " >> $action 2>&1
	if [ `ps -ef | grep -i 'snmp' | grep -v 'grep' | wc -l` -gt 0 ]; then
		echo " > U-66 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " SNMP 서비스를 사용하고 있습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"SNMP 서비스를 사용하고 있습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-66 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"SNMP 서비스를 사용하지 않는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_67() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-67(중) | 3. 서비스 관리 > 3.31 SNMP 서비스 Community String의 복잡성 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"67\", " >> $postdb 2>&1
	echo "  \"id\" : \"67\", " >> $action 2>&1
	echo " 양호 판단 기준 : SNMP Community 이름이 public, private 이 아닌 경우" >> $resultfile 2>&1
	echo "     조치방법 : snmpd.conf 파일에서 커뮤니티명을 확인한 후 디폴트 커뮤니티명인 “public, private”를 추측하기 어려운 커뮤니티명으로 변경 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"snmpd.conf 파일에서 커뮤니티명을 확인한 후 디폴트 커뮤니티명인 “public, private”를 추측하기 어려운 커뮤니티명으로 변경\" " >> $action 2>&1
	ps_snmp_count=`ps -ef | grep -i 'snmp' | grep -v 'grep' | wc -l`
	if [ $ps_snmp_count -gt 0 ]; then
		find_snmpdconf_count=`find / -name 'snmpd.conf' -type f 2>/dev/null | wc -l`
		if [ $find_snmpdconf_count -gt 0 ]; then
			snmpdconf_files=(`find / -name 'snmpd.conf' -type f 2>/dev/null`)
			for ((i=0; i<${#snmpdconf_files[@]}; i++))
			do
				snmpconf_public_private_count=`grep -vE '^#|^\s#' ${snmpdconf_files[$i]} | grep -iE 'public|private' | wc -l`
				if [ $snmpconf_public_private_count -gt 0 ]; then
					echo " > U-67 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " SNMP Community String이 public 또는 private으로 설정되어 있습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"SNMP Community String이 public 또는 private으로 설정되어 있습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		else
			echo " > U-67 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " SNMP 서비스를 사용하고, Community String을 설정하는 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"SNMP 서비스를 사용하고, Community String을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-67 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"SNMP Community 이름이 public, private 이 아닌 경우\" " >> $postdb 2>&1
	return 0
}



U_68() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-68(하) | 3. 서비스 관리 > 3.32 로그온 시 경고 메시지 제공 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"68\", " >> $postdb 2>&1
	echo "  \"id\" : \"68\", " >> $action 2>&1
	echo " 양호 판단 기준 : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 메시지가 설정되어 있는 경우" >> $resultfile 2>&1
	echo " -- DNS 배너의 경우 '/etc/named.conf' 또는 '/var/named' 파일을 수동으로 점검하세요." >> $resultfile 2>&1
	echo "     조치방법 : Telnet, FTP, SMTP, DNS 서비스를 사용할 경우 설정파일 조치 후 inetd 데몬 재시작 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"Telnet, FTP, SMTP, DNS 서비스를 사용할 경우 설정파일 조치 후 inetd 데몬 재시작\" " >> $action 2>&1
	if [ -f /etc/motd ]; then
		if [ `grep -vE '^ *#|^$' /etc/motd | wc -l` -eq 0 ]; then
			echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/motd 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/motd 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " /etc/motd 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/motd 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
	if [ -f /etc/services ]; then
		telnet_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $telnet_port_count -gt 0 ]; then
			telnet_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="telnet" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#telnet_port[@]}; i++))
			do
				netstat_telnet_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${telnet_port[$i]}" | wc -l`
				if [ $netstat_telnet_count -gt 0 ]; then
					if [ -f /etc/issue.net ]; then
						if [ `grep -vE '^ *#|^$' /etc/issue.net | wc -l` -eq 0 ]; then
							echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " telnet 서비스를 사용하고, /etc/issue.net 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/issue.net 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " telnet 서비스를 사용하고, /etc/issue.net 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/issue.net 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	ps_telnet_count=`ps -ef | grep -i 'telnet' | grep -v 'grep' | wc -l`
	if [ $ps_telnet_count -gt 0 ]; then
		if [ -f /etc/issue.net ]; then
			if [ `grep -vE '^ *#|^$' /etc/issue.net | wc -l` -eq 0 ]; then
				echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " telnet 서비스를 사용하고, /etc/issue.net 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/issue.net 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " telnet 서비스를 사용하고, /etc/issue.net 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"telnet 서비스를 사용하고, /etc/issue.net 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	if [ -f /etc/services ]; then
		ftp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $ftp_port_count -gt 0 ]; then
			ftp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="ftp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#ftp_port[@]}; i++))
			do
				netstat_ftp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${ftp_port[$i]}" | wc -l`
				if [ $netstat_ftp_count -gt 0 ]; then
					ftpdconf_file_exists_count=0
					if [ -f /etc/vsftpd.conf ]; then
						((ftpdconf_file_exists_count++))
						vsftpdconf_banner_count=`grep -vE '^#|^\s#' /etc/vsftpd.conf | grep 'ftpd_banner' | awk -F = '$2!=" " {print $2}' | wc -l`
						if [ $vsftpdconf_banner_count -eq 0 ]; then
							echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스를 사용하고, /etc/vsftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/vsftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
					if [ -f /etc/proftpd/proftpd.conf ]; then
						((ftpdconf_file_exists_count++))
						proftpdconf_banner_count=`grep -vE '^#|^\s#' /etc/proftpd/proftpd.conf | grep 'ServerIdent' | wc -l`
						if [ $proftpdconf_banner_count -eq 0 ]; then
							echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스를 사용하고, /etc/proftpd/proftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/proftpd/proftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
					if [ -f /etc/pure-ftpd/conf/WelcomeMsg ]; then
						((ftpdconf_file_exists_count++))
						pureftpd_conf_banner_count=`grep -vE '^ *#|^$' /etc/pure-ftpd/conf/WelcomeMsg | wc -l`
						if [ $pureftpd_conf_banner_count -eq 0 ]; then
							echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " ftp 서비스를 사용하고, /etc/pure-ftpd/conf/WelcomeMsg 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/pure-ftpd/conf/WelcomeMsg 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
							return 0
						fi
					fi
					if [ $ftpdconf_file_exists_count -eq 0 ]; then
						echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ftp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"ftp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
					
				fi
			done
		fi
	fi
	ps_ftp_count=`ps -ef | grep -i 'ftp' | grep -vE 'grep|tftp|sftp' | wc -l`
	if [ $ps_ftp_count -gt 0 ]; then
		ftpdconf_file_exists_count=0
		if [ -f /etc/vsftpd.conf ]; then
			((ftpdconf_file_exists_count++))
			vsftpdconf_banner_count=`grep -vE '^#|^\s#' /etc/vsftpd.conf | grep 'ftpd_banner' | awk -F = '$2!=" " {print $2}' | wc -l`
			if [ $vsftpdconf_banner_count -eq 0 ]; then
				echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ftp 서비스를 사용하고, /etc/vsftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/vsftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
		if [ -f /etc/proftpd/proftpd.conf ]; then
			((ftpdconf_file_exists_count++))
			proftpdconf_banner_count=`grep -vE '^#|^\s#' /etc/proftpd/proftpd.conf | grep 'ServerIdent' | wc -l`
			if [ $proftpdconf_banner_count -eq 0 ]; then
				echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ftp 서비스를 사용하고, /etc/proftpd/proftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/proftpd/proftpd.conf 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
		if [ -f /etc/pure-ftpd/conf/WelcomeMsg ]; then
			((ftpdconf_file_exists_count++))
			pureftpd_conf_banner_count=`grep -vE '^ *#|^$' /etc/pure-ftpd/conf/WelcomeMsg | wc -l`
			if [ $pureftpd_conf_banner_count -eq 0 ]; then
				echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " ftp 서비스를 사용하고, /etc/pure-ftpd/conf/WelcomeMsg 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"ftp 서비스를 사용하고, /etc/pure-ftpd/conf/WelcomeMsg 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
				return 0
			fi
		fi
		if [ $ftpdconf_file_exists_count -eq 0 ]; then
			echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " ftp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"ftp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	if [ -f /etc/services ]; then
		smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $smtp_port_count -gt 0 ]; then
			smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#smtp_port[@]}; i++))
			do
				netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]}" | wc -l`
				if [ $netstat_smtp_count -gt 0 ]; then
					find_sendmailcf_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
					if [ $find_sendmailcf_count -gt 0 ]; then
						sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
						for ((j=0; j<${#sendmailcf_files[@]}; j++))
						do
							sendmailcf_banner_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$j]} | grep 'Smtp' | grep 'GreetingMessage' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
							if [ $sendmailcf_banner_count -eq 0 ]; then
								echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " smtp 서비스를 사용하고, ${sendmailcf_files[$j]} 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"smtp 서비스를 사용하고, ${sendmailcf_files[$j]} 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					else
						echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " smtp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"smtp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
	if [ $ps_smtp_count -gt 0 ]; then
		find_sendmailcf_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
		if [ $find_sendmailcf_count -gt 0 ]; then
			sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
			for ((i=0; i<${#sendmailcf_files[@]}; i++))
			do
				sendmailcf_banner_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$i]} | grep 'Smtp' | grep 'GreetingMessage' | awk -F = '{gsub(" ", "", $0); print $2}' | wc -l`
				if [ $sendmailcf_banner_count -eq 0 ]; then
					echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " smtp 서비스를 사용하고, ${sendmailcf_files[$i]} 파일에 로그온 메시지를 설정하지 않았습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"smtp 서비스를 사용하고, ${sendmailcf_files[$i]} 파일에 로그온 메시지를 설정하지 않았습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		else
			echo " > U-68 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " smtp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"smtp 서비스를 사용하고, 로그온 메시지를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-68 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1 
	echo "  \"결과상세\" : \"서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 메시지가 설정되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_69() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-69(중) | 3. 서비스 관리 > 3.33 NFS 설정파일 접근권한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"69\", " >> $postdb 2>&1
	echo "  \"id\" : \"69\", " >> $action 2>&1
	echo " 양호 판단 기준 : NFS 접근제어 설정파일의 소유자가 root 이고, 권한이 644 이하인 경우" >> $resultfile 2>&1
	echo "     조치방법 : NFS 접근제어 설정파일의 소유자가 root 가 아니거나, 권한이 644 이하가 아닌 경우 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"NFS 접근제어 설정파일의 소유자가 root 가 아니거나, 권한이 644 이하가 아닌 경우\" " >> $action 2>&1
	if [ -f /etc/exports ]; then
		etc_exports_owner_name=`ls -l /etc/exports | awk '{print $3}'`
		if [[ $etc_exports_owner_name =~ root ]]; then
			etc_exports_permission=`stat /etc/exports | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,3)}'`
			if [ $etc_exports_permission -le 644 ]; then
				etc_exports_owner_permission=`stat /etc/exports | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,3,1)}'`
				if [ $etc_exports_owner_permission -eq 6 ] || [ $etc_exports_owner_permission -eq 4 ] || [ $etc_exports_owner_permission -eq 2 ] || [ $etc_exports_owner_permission -eq 0 ]; then
					etc_exports_group_permission=`stat /etc/exports | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,4,1)}'`
					if [ $etc_exports_group_permission -eq 4 ] || [ $etc_exports_group_permission -eq 0 ]; then
						etc_exports_other_permission=`stat /etc/exports | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
						if [ $etc_exports_other_permission -eq 4 ] || [ $etc_exports_other_permission -eq 0 ]; then
							echo " > U-69 결과 : 양호(Good)" >> $resultfile 2>&1
							echo "  \"결과\" : \"양호\", " >> $postdb 2>&1 
							echo "  \"결과상세\" : \"NFS 접근제어 설정파일의 소유자가 root 이고, 권한이 644 이하인 경우\" " >> $postdb 2>&1
							return 0
						else
							echo " > U-69 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
							echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
							echo " /etc/exports 파일의 다른 사용자(other)에 대한 권한이 취약합니다." >> $resultfile 2>&1
							echo "  \"결과상세\" : \"/etc/exports 파일의 다른 사용자(other)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
							return 0
						fi
					else
						echo " > U-69 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " /etc/exports 파일의 그룹 사용자(group)에 대한 권한이 취약합니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"/etc/exports 파일의 그룹 사용자(group)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-69 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " /etc/exports 파일의 사용자(owner)에 대한 권한이 취약합니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"/etc/exports 파일의 사용자(owner)에 대한 권한이 취약합니다.\" " >> $postdb 2>&1
					return 0
				fi
			else
				echo " > U-69 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
				echo " /etc/exports 파일의 권한이 644보다 큽니다." >> $resultfile 2>&1
				echo "  \"결과상세\" : \"/etc/exports 파일의 권한이 644보다 큽니다.\" " >> $postdb 2>&1
				return 0
			fi
		else
			echo " > U-69 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " /etc/exports 파일의 소유자(owner)가 root가 아닙니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"/etc/exports 파일의 소유자(owner)가 root가 아닙니다.\" " >> $postdb 2>&1
			return 0
		fi
	else
		echo " > U-69 결과 : N/A" >> $resultfile 2>&1
		echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
		echo " /etc/exports 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"/etc/exports 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	fi
}



U_70() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-70(중) | 3. 서비스 관리 > 3.34 expn, vrfy 명령어 제한 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"70\", " >> $postdb 2>&1
	echo "  \"id\" : \"70\", " >> $action 2>&1
	echo " 양호 판단 기준 : SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : SMTP 서비스 설정파일에 noexpn, novrfy 또는 goaway 옵션 추가 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"SMTP 서비스 설정파일에 noexpn, novrfy 또는 goaway 옵션 추가\" " >> $action 2>&1
	if [ -f /etc/services ]; then
		smtp_port_count=`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}' | wc -l`
		if [ $smtp_port_count -gt 0 ]; then
			smtp_port=(`grep -vE '^#|^\s#' /etc/services | awk 'tolower($1)=="smtp" {print $2}' | awk -F / 'tolower($2)=="tcp" {print $1}'`)
			for ((i=0; i<${#smtp_port[@]}; i++))
			do
				netstat_smtp_count=`netstat -nat 2>/dev/null | grep -w 'tcp' | grep -Ei 'listen|established|syn_sent|syn_received' | grep ":${smtp_port[$i]}" | wc -l`
				if [ $netstat_smtp_count -gt 0 ]; then
					find_sendmailcf_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
					if [ $find_sendmailcf_count -gt 0 ]; then
						sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
						for ((j=0; j<${#sendmailcf_files[@]}; j++))
						do
							sendmailcf_goaway_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$j]} | grep -i 'PrivacyOptions' | grep -i 'goaway' | wc -l`
							sendmailcf_noexpnt_novrfy_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$j]} | grep -i 'PrivacyOptions' | grep -i 'noexpn' | grep -i 'novrfy' | wc -l`
							if [ $sendmailcf_goaway_count -eq 0 ] && [ $sendmailcf_noexpnt_novrfy_count -eq 0 ]; then
								echo " > U-70 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
								echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
								echo " ${sendmailcf_files[$j]} 파일에 noexpn, novrfy 또는 goaway 설정이 없습니다." >> $resultfile 2>&1
								echo "  \"결과상세\" : \"${sendmailcf_files[$j]} 파일에 noexpn, novrfy 또는 goaway 설정이 없습니다.\" " >> $postdb 2>&1
								return 0
							fi
						done
					else
						echo " > U-70 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " noexpn, novrfy 또는 goaway 옵션을 설정하는 파일이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"noexpn, novrfy 또는 goaway 옵션을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				fi
			done
		fi
	fi
	ps_smtp_count=`ps -ef | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l`
	if [ $ps_smtp_count -gt 0 ]; then
		find_sendmailcf_count=`find / -name 'sendmail.cf' -type f 2>/dev/null | wc -l`
		if [ $find_sendmailcf_count -gt 0 ]; then
			sendmailcf_files=(`find / -name 'sendmail.cf' -type f 2>/dev/null`)
			for ((i=0; i<${#sendmailcf_files[@]}; i++))
			do
				sendmailcf_goaway_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$i]} | grep -i 'PrivacyOptions' | grep -i 'goaway' | wc -l`
				sendmailcf_noexpnt_novrfy_count=`grep -vE '^#|^\s#' ${sendmailcf_files[$i]} | grep -i 'PrivacyOptions' | grep -i 'noexpn' | grep -i 'novrfy' | wc -l`
				if [ $sendmailcf_goaway_count -eq 0 ] && [ $sendmailcf_noexpnt_novrfy_count -eq 0 ]; then
					echo " > U-70 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${sendmailcf_files[$i]} 파일에 noexpn, novrfy 또는 goaway 설정이 없습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${sendmailcf_files[$i]} 파일에 noexpn, novrfy 또는 goaway 설정이 없습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		else
			echo " > U-70 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
			echo " noexpn, novrfy 또는 goaway 옵션을 설정하는 파일이 없습니다." >> $resultfile 2>&1
			echo "  \"결과상세\" : \"noexpn, novrfy 또는 goaway 옵션을 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
			return 0
		fi
	fi
	echo " > U-70 결과 : 양호(Good)" >> $resultfile 2>&1
	echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
	echo "  \"결과상세\" : \"SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우\" " >> $postdb 2>&1
	return 0
}



U_71() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-71(중) | 3. 서비스 관리 > 3.35 Apache 웹 서비스 정보 숨김 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"서비스 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"71\", " >> $postdb 2>&1
	echo "  \"id\" : \"71\", " >> $action 2>&1
	echo " 양호 판단 기준 : ServerTokens Prod, ServerSignature Off로 설정되어있는 경우" >> $resultfile 2>&1
	echo "     조치방법 : 헤더에 최소한의 정보를 제한 후 전송 (ServerTokens 지시자에 Prod 옵션, ServerSignature 지시자에 Off 옵션 설정) " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"헤더에 최소한의 정보를 제한 후 전송 (ServerTokens 지시자에 Prod 옵션, ServerSignature 지시자에 Off 옵션 설정)\" " >> $action 2>&1
	webconf_file_exists_count=0
	webconf_files=(".htaccess" "httpd.conf" "apache2.conf")
	for ((i=0; i<${#webconf_files[@]}; i++))
	do
		find_webconf_file_count=`find / -name ${webconf_files[$i]} -type f 2>/dev/null | wc -l`
		if [ $find_webconf_file_count -gt 0 ]; then
			((webconf_file_exists_count++))
			find_webconf_files=(`find / -name ${webconf_files[$i]} -type f 2>/dev/null`)
			for ((j=0; j<${#find_webconf_files[@]}; j++))
			do
				webconf_servertokens_prod_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'ServerTokens' | grep -i 'Prod' | wc -l`
				if [ $webconf_servertokens_prod_count -gt 0 ]; then
					webconf_serversignature_off_count=`grep -vE '^#|^\s#' ${find_webconf_files[$j]} | grep -i 'ServerSignature' | grep -i 'Off' | wc -l`
					if [ $webconf_serversignature_off_count -eq 0 ]; then
						echo " > U-71 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
						echo " ${find_webconf_files[$j]} 파일에 ServerSignature off 설정이 없습니다." >> $resultfile 2>&1
						echo "  \"결과상세\" : \"${find_webconf_files[$j]} 파일에 ServerSignature off 설정이 없습니다.\" " >> $postdb 2>&1
						return 0
					fi
				else
					echo " > U-71 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
					echo " ${find_webconf_files[$j]} 파일에 ServerTokens Prod 설정이 없습니다." >> $resultfile 2>&1
					echo "  \"결과상세\" : \"${find_webconf_files[$j]} 파일에 ServerTokens Prod 설정이 없습니다.\" " >> $postdb 2>&1
					return 0
				fi
			done
		fi
	done
	ps_apache_count=`ps -ef | grep -iE 'httpd|apache2' | grep -v 'grep' | wc -l`
	if [ $ps_apache_count -gt 0 ] && [ $webconf_file_exists_count -eq 0 ]; then
		echo " > U-71 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		echo "  \"결과\" : \"취약\", " >> $postdb 2>&1
		echo " Apache 서비스를 사용하고, ServerTokens Prod, ServerSignature Off를 설정하는 파일이 없습니다." >> $resultfile 2>&1
		echo "  \"결과상세\" : \"Apache 서비스를 사용하고, ServerTokens Prod, ServerSignature Off를 설정하는 파일이 없습니다.\" " >> $postdb 2>&1
		return 0
	else
		echo " > U-71 결과 : 양호(Good)" >> $resultfile 2>&1
		echo "  \"결과\" : \"양호\", " >> $postdb 2>&1
		echo "  \"결과상세\" : \"ServerTokens Prod, ServerSignature Off로 설정되어있는 경우\" " >> $postdb 2>&1
		return 0
	fi
}



U_72() {
	echo ""  >> $resultfile 2>&1
	echo " }, " >> $postdb 2>&1
	echo " { " >> $postdb 2>&1 
	echo " }, " >> $action 2>&1
	echo " { " >> $action 2>&1
	echo " U-72(하) | 5. 로그 관리 > 5.2 정책에 따른 시스템 로깅 설정 "  >> $resultfile 2>&1
	echo "  \"분류\" : \"로그 관리\", " >> $postdb 2>&1
	echo "  \"id\" : \"72\", " >> $postdb 2>&1
	echo "  \"id\" : \"72\", " >> $action 2>&1
	echo " 양호 판단 기준 : 로그 기록 정책이 정책에 따라 설정되어 수립되어 있으며 보안 정책에 따라 로그를 남기고 있을 경우" >> $resultfile 2>&1
	echo "     조치방법 : 로그 기록 정책을 수립하고, 정책에 따라 syslog.conf 파일을 설정 " >> $resultfile 2>&1
	echo "  \"조치방법\" : \"로그 기록 정책을 수립하고, 정책에 따라 syslog.conf 파일을 설정\" } " >> $action 2>&1
	echo " > U-72 결과 : N/A" >> $resultfile 2>&1
	echo "  \"결과\" : \"N/A\", " >> $postdb 2>&1
	echo " 수동으로 점검하세요." >> $resultfile 2>&1
	echo "  \"결과상세\" : \"수동으로 점검하세요.\" " >> $postdb 2>&1
	echo " } " >> $action 2>&1
	echo "] " >> $action 2>&1
	echo " } " >> $postdb 2>&1
	echo "] " >> $postdb 2>&1
}

echo ""  > $resultfile 2>&1
echo " 점검일 : `date +'%F %H:%M:%S'`"  >> $resultfile 2>&1
echo "------------------------------------------------------------------------------" >> $resultfile 2>&1
echo "#                                                                            #" >> $resultfile 2>&1
echo "#          Fedora 38 vulnerability assessment results Version 0.0.2          #" >> $resultfile 2>&1
echo "#                               강김홍차 -  2024                               #" >> $resultfile 2>&1
echo "#                                                                            #" >> $resultfile 2>&1
echo "------------------------------------------------------------------------------" >> $resultfile 2>&1

U_01
U_02
U_03
U_04
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
U_16
U_17
U_18
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_42
U_43
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
U_55
U_56
U_57
U_58
U_59
U_60
U_61
U_62
U_63
U_64
U_65
U_66
U_67
U_68
U_69
U_70
U_71
U_72

echo "[" >> $statis 2>&1
echo " {" >> $statis 2>&1
echo "  \"항목 개수\" : \"$(cat $resultfile | grep '결과 : ' | wc -l)\", " >> $statis 2>&1
echo "  \"취약 개수\" : \"$(cat $resultfile | grep '결과 : 취약' | wc -l)\", " >> $statis 2>&1
echo "  \"양호 개수\" : \"$(cat $resultfile | grep '결과 : 양호' | wc -l)\", " >> $statis 2>&1
echo "  \"N/A 개수\" : \"$(cat $resultfile | grep '결과 : N/A' | wc -l)\" " >> $statis 2>&1
echo " }" >> $statis 2>&1
echo "]" >> $statis 2>&1

echo ""  >> $resultfile 2>&1
echo "================================ 진단 결과 요약 ================================" >> $resultfile 2>&1
echo ""  >> $resultfile 2>&1
echo "                               항목 개수 = `cat $resultfile | grep '결과 : ' | wc -l`" >> $resultfile 2>&1
echo "                               취약 개수 = `cat $resultfile | grep '결과 : 취약' | wc -l`" >> $resultfile 2>&1
echo "                               양호 개수 = `cat $resultfile | grep '결과 : 양호' | wc -l`" >> $resultfile 2>&1
echo "                               N/A 개수 = `cat $resultfile | grep '결과 : N/A' | wc -l`" >> $resultfile 2>&1
echo ""  >> $resultfile 2>&1
echo "==============================================================================" >> $resultfile 2>&1
echo ""  >> $resultfile 2>&1

libreoffice --headless --convert-to pdf $resultfile > /dev/null
