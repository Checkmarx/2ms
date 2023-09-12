help_message=$(go run .)

echo "" >output.txt
echo '```' >>output.txt
echo "$help_message" >>output.txt
echo '```' >>output.txt
echo "" >>output.txt

sed -i '/<!-- command-line:start -->/,/<!-- command-line:end -->/{
            /<!-- command-line:start -->/{
              p
              r output.txt
            }
            /<!-- command-line:end -->/!d
          }' README.md

rm output.txt

git --no-pager diff README.md
