import cmd
import sys
import importlib.util
import os

class EmojiShell(cmd.Cmd):
    prompt = '(emojiShell) '
    intro = 'Enter an emoji to run tool. Type "exit" to quit.'

    def default(self, line):
        emoji = line.strip()
        file_path = f'{emoji}.py'
        if os.path.exists(file_path):
            try:
                spec = importlib.util.spec_from_file_location("module", file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as e:
                print(f"Error executing {emoji}.py: {e}")
        else:
            print(f"No tool found for emoji: {emoji}")

    def do_exit(self, arg):
        return True

if __name__ == '__main__':
    EmojiShell().cmdloop()
