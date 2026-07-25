import subprocess


def run_user_command(command: str) -> None:
    subprocess.run(command, shell=True, check=True)
