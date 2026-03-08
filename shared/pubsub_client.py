import json
from google.cloud import pubsub_v1
from shared.config import PROJECT_ID

publisher = pubsub_v1.PublisherClient()
subscriber = pubsub_v1.SubscriberClient()

def publish_message(topic_path: str, message: dict) -> str:
    data = json.dumps(message, default=str).encode('utf-8')
    future = publisher.publish(topic_path, data)
    message_id = future.result()
    print(f'Published message {message_id} to {topic_path}')
    return message_id

def pull_messages(subscription_path: str, max_messages: int = 10):
    response = subscriber.pull(request={'subscription': subscription_path, 'max_messages': max_messages})
    return response.received_messages

def acknowledge_message(subscription_path: str, ack_id: str):
    subscriber.acknowledge(request={'subscription': subscription_path, 'ack_ids': [ack_id]})
