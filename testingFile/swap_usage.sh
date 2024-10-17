#!/bin/bash

# 메모리 사용 정보 추출
swap_info=$(top -bn1 | grep "MiB Swap" | awk '{print $3, $7, $9}')

# 현재 스왑 메모리 사용 정보를 수집
total_swap=$(echo "$swap_info" | awk '{print $1}')
used_swap=$(echo "$swap_info" | awk '{print $2}')
available_swap=$(echo "$swap_info" | awk '{print $3}')

#--------------------------------------

# JSON 파일의 경로
json_file="SMemory.json"

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
                --arg total "$total_swap" \
                --arg used "$used_swap" \
                --arg available "$available_swap" \
                '. += [{
                    "hour": $hour,
                    "총 스왑 메모리": ($total | tonumber),
                    "사용 중인 스왑 메모리": ($used | tonumber),
                    "사용 가능한 스왑 메모리": ($available | tonumber)
                }]' <<< "$json_content")

# JSON 파일에 새로운 데이터 저장
echo "$new_entry" | jq . > "$json_file"
echo "1. Swap Memory 검사 완료"