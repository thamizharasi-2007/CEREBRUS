from benign_task import BENIGN_TASKS


def run_benign_task(task):

    print("\n" + "=" * 60)
    print(f"RUNNING {task['id']}")
    print("=" * 60)

    print("User task:")
    print(task["prompt"])

    print("\nExpected workflow:")

    for step_number, step in enumerate(task["workflow"], start=1):
        print(f"  Step {step_number}: {step}")

    print("\nExpected tools:")

    for tool in task["expected_tools"]:
        print(f"  - {tool}")

    print("\nExpected Cerebrus decision:")
    print(f"  {task['expected_decision']}")

    print("\nWorkflow loaded successfully.")

    return True


def run_all_benign_tasks():

    print("\n")
    print("=" * 60)
    print("CEREBRUS BENIGN WORKFLOW RUNNER")
    print("=" * 60)

    total = len(BENIGN_TASKS)
    passed = 0
    failed = 0

    for task in BENIGN_TASKS:

        try:
            success = run_benign_task(task)

            if success:
                passed += 1
            else:
                failed += 1

        except Exception as error:
            print(f"\n[ERROR] {task['id']}")
            print(error)
            failed += 1

    print("\n" + "=" * 60)
    print("BENIGN WORKFLOW RUNNER RESULT")
    print("=" * 60)

    print(f"Total : {total}")
    print(f"Loaded: {passed}")
    print(f"Failed: {failed}")

    if failed == 0:
        print("\nAll 30 workflows loaded successfully.")
    else:
        print("\nSome workflows failed to load.")


if __name__ == "__main__":
    run_all_benign_tasks()