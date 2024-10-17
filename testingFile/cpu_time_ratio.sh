#!/bin/bash

# CPU 시간 비율 추출
cpu_time=$(mpstat -P ALL 1 1 | awk '$12 ~ /[0-9.]+/ {print $5, $7, $14}' | head -1)

# 사용자 시간, 시스템 시간, 유휴 시간 추출
user_time=$(echo "$cpu_time" | awk '{print $1}')
system_time=$(echo "$cpu_time" | awk '{print $2}')
idle_time=$(echo "$cpu_time" | awk '{print $3}')

#---------------------------------------

# JSON 파일 경로
json_file="CpuTime.json"

# 기존 JSON 파일에서 데이터를 읽어오기
if [ -f "$json_file" ]; then
    json_content=$(cat "$json_file")
else
    json_content="[]"
fi

# 현재 카운터 값 가져오기
counter=$(echo "$json_content" | jq 'length')

# JSON 형식으로 새 데이터 추가
new_entry=$(jq --argjson hour "$((counter + 1))" \
                --arg user "$user_time" \
                --arg system "$system_time" \
                --arg idle "$idle_time" \
                '. += [{
                    "hour": $hour,
                    "사용자 시간": ($user | tonumber),
                    "시스템 시간": ($system | tonumber),
                    "유휴 시간": ($idle | tonumber)
                }]' <<< "$json_content")

# JSON 파일에 새로운 데이터 저장
echo "$new_entry" | jq . > "$json_file"
echo "3. Cpu 사용시간 검사 완료"
