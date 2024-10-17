#!/bin/bash

# MongoDB Atlas 연결 정보
MONGO_URI="mongodb+srv://admin:NrLJhyWCPsAw2Jcz@cluster0.7anrpml.mongodb.net/$1?retryWrites=true&w=majority"

# 인자로 데이터베이스 이름을 받음 (웹에서 )
if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <database_name>"
	exit 1
fi

DATABASE_NAME="$1"

# JSON 파일 경로 (적절히 수정하세요)
BASE_PATH="/home/jin/testData"
JSON_FILES=(
    "$BASE_PATH/ChartData.json"
    "$BASE_PATH/TextData.json"
    "$BASE_PATH/CpuData.json"
    "$BASE_PATH/CpuTime.json"
    "$BASE_PATH/SMemory.json"
    "$BASE_PATH/VMemory.json"
    "$BASE_PATH/Solutions.json"
)

echo -e "[MongoDB 데이터 임포트 \033[32m시작\033[0m]"

# 모든 파일이 성공적으로 업로드되었는지를 추적하는 변수
all_success=true

# 각각의 파일을 해당 컬렉션에 삽입
for FILE in "${JSON_FILES[@]}"; do
    # 파일 이름에서 컬렉션 이름 추출 (예: file1.json -> file1)
    COLLECTION_NAME=$(basename "$FILE" .json)

    # mongoimport 명령어 실행
    mongoimport --uri="$MONGO_URI" --collection="$COLLECTION_NAME" --file="$FILE" --jsonArray

    # 결과 확인
    if [ $? -eq 0 ]; then
        echo -e "$FILE 을 $COLLECTION_NAME 콜렉션에 업로드 \033[32m성공\033[0m"
    else
        echo -e "\033[31m$FILE 임포트에 실패\033[0m"
        all_success=false  # 하나라도 실패하면 false로 변경
    fi

    echo "--------------------------------"

done
echo -e "[MongoDB 데이터 임포트 \033[31m종료\033[0m]"

# 모든 파일이 성공적으로 업로드되었는지 확인
if $all_success; then
    echo -e "모든 파일의 업로드 \033[32m성공\033[0m"
    echo "testData 파일을 삭제합니다."
    rm -rf testData
else
    echo -e "\033[32m하나 이상의 파일이 업로드에 실패했습니다.\033[0m"
    echo "testData 파일을 열어 수동으로 임포트하세요."
fi
