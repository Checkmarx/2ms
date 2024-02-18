update_readme() {
  output_file=$1
  placeholder_name=$2
  target_file=$3

  sed -i "/<!-- $placeholder_name:start -->/,/<!-- $placeholder_name:end -->/{
            /<!-- $placeholder_name:start -->/{
              p
              r $output_file
            }
            /<!-- $placeholder_name:end -->/!d
          }" $target_file
}

# Update the README with the help message
help_message=$(go run .)

echo "" >output.txt
echo '```' >>output.txt
echo "$help_message" >>output.txt
echo '```' >>output.txt
echo "" >>output.txt
update_readme "output.txt" "command-line" "README.md"
rm output.txt

go run . rules | awk 'BEGIN{FS = "   *"}{print "| " $1 " | " $2 " | " $3 " | " $4 " |";}' >output.txt
update_readme "output.txt" "table" "./docs/list-of-rules.md"
rm output.txt

git --no-pager diff README.md ./docs/list-of-rules.md
