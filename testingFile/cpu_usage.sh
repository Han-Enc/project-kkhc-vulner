#!/bin/bash

# 각 CPU 코어의 사용률을 저장할 배열
declare -a cpu_usage=()

# 전체 CPU 사용률 계산
total_cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{printf("%d\n", 100 - $8)}')

# 각 CPU 코어의 사용률을 배열에 저장
cpu_info=$(mpstat -P ALL 1 1 | awk '$12 ~ /[0-9.]+/ {print $NF}')
cpu_usage=()  # 배열 초기화
while read -r line; do
    cpu_usage+=("$line")
done <<< "$cpu_info"

# P.C와 L.C 사용률 및 코어 수의 기본값 설정
pc_usage=0
lc_usage=0
pc_cores=$(nproc)
lc_cores=$(nproc)

# 사용률이 존재하는 경우에만 값 설정
if [ ${#cpu_usage[@]} -gt 1 ]; then
    # cpu_usage[1]의 %idle 값을 가져와서 CPU 사용률 계산
    idle_value1=$(echo "${cpu_usage[1]}" | awk '{print int($1)}')
    # 100에서 정수값을 뺀다
    pc_usage=$(( 100 - idle_value1 ))
fi
if [ ${#cpu_usage[@]} -gt 2 ]; then
    # cpu_usage[2]의 %idle 값을 가져와서 CPU 사용률 계산
    idle_value2=$(echo "${cpu_usage[2]}" | awk '{print int($1)}')
    # 100에서 정수값을 뺀다
    lc_usage=$(( 100 - idle_value2 ))
fi

# JSON 파일 경로
json_file="CpuData.json"

# 기존 JSON 파일에서 데이터를 읽어오기
if [ -f "$json_file" ]; then
    json_content=$(cat "$json_file")
else
    json_content="[]"
fi

# 현재 카운터 값 가져오기
counter=$(echo "$json_content" | jq 'length')

# 현재 시간과 카운터 값을 사용하여 새로운 데이터 추가
new_entry=$(jq --argjson hour "$((counter + 1))" \
                --arg total "$total_cpu_usage" \
                --arg pc_usage "$pc_usage" \
                --arg lc_usage "$lc_usage" \
                --arg pc_cores "$pc_cores" \
                --arg lc_cores "$lc_cores" \
                '. += [{
                    "hour": ($hour | tonumber),
                    "전체 CPU 사용률": ($total | tonumber),
                    "P.C CPU 사용률": ($pc_usage | tonumber),
                    "L.C CPU 사용률": ($lc_usage | tonumber),
                    "P.C 코어 수": ($pc_cores | tonumber),
                    "L.C 코어 수": ($lc_cores | tonumber)
                }]' <<< "$json_content")

# JSON 파일에 새로운 데이터 저장
echo "$new_entry" | jq . > "$json_file"
echo "4. Cpu 사용량 검사 완료"