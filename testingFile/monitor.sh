#!/bin/bash

# 패키지 목록
packages1=("procps-ng" "sysstat")
packages2=("jq" "sysstat")

# 패키지 업데이트
echo "검사에 필요한 패키지 목록 업데이트 중..."
sudo dnf check-update

# 첫 번째 패키지 설치
echo "설치 중: ${packages1[*]}"
sudo dnf install -y "${packages1[@]}"

# 두 번째 패키지 설치
echo "설치 중: ${packages2[*]}"
sudo dnf install -y "${packages2[@]}"

echo "모든 패키지가 설치되었습니다."

echo "--------------------------------"

#------------------------------

# 권한을 -x로 상승시키는 파일 리스트
files=("cpu_usage.sh" "cpu_time_ratio.sh" "vm_usage.sh" "swap_usage.sh" "main_test.sh")

for file in "${files[@]}"; do
    chmod +x "$file"
done

#------------------------------

#main_test.sh 실행
./main_test.sh &
echo -e "[취약점 검사 \033[1;32m시작\033[0m]"       # 키워드 색상 넣어 가시성 높임
echo "잠시만 기다려주세요."

while true
do
        # main_test.sh 실행 확인
        check=$(ps -ef | grep "main_test.sh" | grep -v "grep")

                echo "검사가 진행되는 동안 자원 모니터링 중"

        # main_test.sh 모니터링
        if [ "$check" != "" ]; then
                
                # 4개의 쉘 스크립트 동시에 실행
                ./cpu_usage.sh &
                pid1=$!

                ./cpu_time_ratio.sh &
                pid2=$!

                ./vm_usage.sh &
                pid3=$!

                ./swap_usage.sh &
                pid4=$!

                # 모든 백그라운드 작업이 완료될 때까지 기다리기
                wait $pid1
                wait $pid2
                wait $pid3
                wait $pid4
                echo "--------------------------------"

                # main_test.sh가 여전히 실행 중인 경우 잠시 대기
				sleep 3
        else
                echo -e "[취약점 검사 \033[1;31m종료\033[0m]"    # 키워드 색상 넣어 가시성 높임
                break
        fi
done