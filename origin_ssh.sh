#!/bin/bash

# 사용자로부터 SSH 연결 정보 입력 받기
read -p "연결할 사용자 이름을 입력하세요: " USERNAME
read -p "연결할 호스트의 IP 주소 또는 도메인 이름을 입력하세요: " HOSTNAME

# sudo 비밀번호 입력 받기
echo -n "root 비밀번호를 입력하세요: "
read -s SUDO_PASSWORD
echo # 줄 바꿈

# 전송할 파일 경로
FILE_PATH="testingFile.zip"

# 상대 리눅스에 파일 전송
echo "취약점 검사 및 운영체제 모니터링 파일 전송 중..."
scp "$FILE_PATH" "$USERNAME@$HOSTNAME:~/"

if [ $? -ne 0 ]; then
    echo "파일 전송 실패. 종료합니다."
    exit 1
fi

# SSH 연결 및 명령어 실행
echo "상대와 SSH 연결 중..."
ssh "$USERNAME@$HOSTNAME" << EOF
    echo "--------------------------------"
    echo "검사 파일 압축 해제 중..."
    unzip testingFile.zip -d testingFile  # testingFile로 압축 해제
    cd testingFile  # 압축 해제된 폴더로 이동

    # 비밀번호를 통해 sudo 명령어 실행
    echo "$SUDO_PASSWORD" | sudo -S bash monitor.sh

    echo "--------------------------------"

    # 검사가 완료된 sh 파일 및 여분의 txt 파일 삭제
    rm -rf *.sh && rm -rf *.txt

    # 현재 디렉토리 이름 저장
    current_dir=\$(basename "\$PWD")

    # 압축할 파일 이름
    zip_file="testData.zip"
    
    # 현재 디렉토리의 모든 파일을 압축
    echo "압축 중: \$zip_file"
    zip -r "\$zip_file" ./*

    # 내 리눅스에 파일 전송 (하드코딩된 IP 및 경로)
    echo "검사 결과 전송 중..."
    sshpass -p "jin1024*" scp "\$zip_file" jin@192.168.240.134:/home/jin/

    # 현재 디렉토리 삭제
    echo "검사에 사용된 정크 데이터 삭제 중..."
    cd .. && rm -rf "\$current_dir"*

    echo "SSH 원격 작업 완료"
    echo "--------------------------------"
EOF

# 검사 결과 압축 해제
unzip testData.zip -d /home/jin/testData
echo "--------------------------------"

# Mongo DB에 데이터 파일 업데이트
read -p "검사 결과를 업로드할 DataBase ID를 입력하세요: " DB

echo "검사 결과를 DB에 업로드 중..."
bash move_to_DB.sh "$DB"

# Xshell을 이용해 관리자 Windows에 pdf 형태 검사 결과 전송
echo "PDF로 검사 결과를 확인하고 게시글을 업데이트 하세요."
sz testData.zip
# sz /home/jin/testData/*.pdf <오류나서 일단 주석
rm -f "testData.zip"  # testData.zip 파일 삭제