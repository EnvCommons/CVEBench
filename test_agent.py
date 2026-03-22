"""End-to-end agent test for CVE-Bench with rollout logging to OpenReward."""

import asyncio
import json
import os

from openai import AsyncOpenAI
from openreward import OpenReward


async def main():
    or_client = OpenReward()
    oai_client = AsyncOpenAI()

    ENV_NAME = "GeneralReasoning/CVEBench"
    SPLIT = "test"

    environment = or_client.environments.get(name=ENV_NAME)
    tasks = await environment.list_tasks(split=SPLIT)
    tools = await environment.list_tools(format="openai")

    # Pick a single task for testing
    task = tasks[0]
    print(f"Testing task: {task.task_spec['id']}")

    rollout = or_client.rollout.create(
        run_name="cvebench_test",
        rollout_name=f"test_{task.task_spec['id']}",
        environment=ENV_NAME,
        split=SPLIT,
        task_spec=task.task_spec,
    )

    async with environment.session(
        task=task,
        secrets={
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "api_key": os.getenv("OPENREWARD_API_KEY"),
        },
    ) as session:
        prompt = await session.get_prompt()
        input_list = [{"role": "user", "content": prompt[0].text}]
        finished = False

        rollout.log_openai_response(message=input_list[0], is_finished=finished)

        while not finished:
            response = await oai_client.responses.create(
                model="o3",
                tools=tools,
                input=input_list,
            )

            rollout.log_openai_response(response.output[-1])
            input_list += response.output

            for item in response.output:
                if item.type == "function_call":
                    tool_result = await session.call_tool(
                        item.name, json.loads(str(item.arguments))
                    )

                    reward = tool_result.reward
                    finished = tool_result.finished

                    input_list.append({
                        "type": "function_call_output",
                        "call_id": item.call_id,
                        "output": tool_result.blocks[0].text,
                    })

                    rollout.log_openai_response(
                        input_list[-1],
                        reward=reward,
                        is_finished=finished,
                    )

                    if finished:
                        break

    print(f"Done. Reward: {reward}")


if __name__ == "__main__":
    asyncio.run(main())
