from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List
import subprocess
import re
# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class Monitoragent():
    """Monitoragent crew"""

    agents: List[BaseAgent]
    tasks: List[Task]

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    
    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def monitor(self) -> Agent:
        return Agent(
            config=self.agents_config['monitor'], # type: ignore[index]
            verbose=True
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def monitor_task(self) -> Task:
        return Task(
            config=self.tasks_config['monitor_task'], # type: ignore[index]
            function = self.detect_connected_devices
        )
    
    def detect_connected_devices(self):
        """Detect connected devices on the local network"""
        try:
            # Run 'arp -a' to get a list of connected devices
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            lines = result.stdout.splitlines()

            devices = []
            for line in lines:
                match = re.match(r'(\S+)\s+(\S+)\s+(\S+)', line)
                if match:
                    hostname, ip, mac = match.groups()
                    devices.append({"Hostname": hostname, "IP": ip, "MAC": mac})

            if not devices:
                return "No connected devices detected."

            # Format as markdown table for CrewAI’s report
            table = "| Hostname | IP Address | MAC Address |\n|-----------|-------------|--------------|\n"
            for d in devices:
                table += f"| {d['Hostname']} | {d['IP']} | {d['MAC']} |\n"

            return table

        except Exception as e:
            return f"Error while detecting devices: {e}"

    @crew
    def crew(self) -> Crew:
        """Creates the Monitoragent crew"""
        # To learn how to add knowledge sources to your crew, check out the documentation:
        # https://docs.crewai.com/concepts/knowledge#what-is-knowledge

        return Crew(
            agents=self.agents, # Automatically created by the @agent decorator
            tasks=self.tasks, # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )
