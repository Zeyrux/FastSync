SESSION="fastSync"

tmux has-session -t $SESSION 2>/dev/null

if [ $? != 0 ]; then
    tmux new-session -d -s $SESSION -n "Neovim"
    tmux send-keys -t $SESSION:0 'nvim .' C-m
    tmux new-window -t $SESSION -n "Console"
    tmux send-keys -t $SESSION:1 'cd ./build' C-m
    tmux split-window -h -t $SESSION:1
    tmux send-keys -t $SESSION:1.1 'cd ./build' C-m
    tmux select-window -t $SESSION:0
fi

tmux attach-session -t $SESSION
