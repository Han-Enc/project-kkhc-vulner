#!/bin/bash

# 메모리 사용 정보 추출
memory_info=$(top -bn1 | grep "MiB Mem" | awk '{print $4, $8, $6}')

# 현재 메모리 사용 정보를 수집
total_memory=$(echo "$memory_info" | awk '{print $1}')
used_memory=$(echo "$memory_info" | awk '{print $2}')
available_memory=$(echo "$memory_info" | awk '{print $3}')
memory_usage=$(echo "$memory_info" | awk '{printf("%d\n", $2/$1 * 100.0)}')

# 정수만 가능한 경우 하기 코드로 변환
total_memory=$(echo "$memory_info" | awk '{print int($1)}')
used_memory=$(echo "$memory_info" | awk '{print int($2)}')
available_memory=$(echo "$memory_info" | awk '{print int($3)}')
memory_usage=$(echo "$memory_info" | awk '{printf("%d\n", $2/$1 * 100.0)}')

#---------------------------------------

# JSON 파일의 경로
json_file="VMemory.json"

# 기존 JSON 파일에서 데이터를 읽어오기
if [ -f "$json_file" ]; then
    json_content=$(cat "$json_file")
else
    json_content="[]"
fi

# 현재 카운터 값 가져오기
counter=$(echo "$json_content" | jq 'length')

# JSON 형식으로 데이터 생성
new_entry=$(jq --argjson hour "$((counter + 1))" \
                --arg total "$total_memory" \
                --arg used "$used_memory" \
                --arg available "$available_memory" \
                --arg usage "$memory_usage" \
                '. += [{
                    "hour": $hour,
                    "총 메모리": ($total | tonumber),
                    "사용 중인 메모리": ($used  | tonumber),
                    "사용 가능한 메모리": ($available | tonumber),
                    "메모리 사용률": ($usage | tonumber)
                }]' <<< "$json_content")


# JSON 파일에 새로운 데이터 저장
echo "$new_entry" | jq . > "$json_file"
echo "2. Virtual Memory 검사 완료"