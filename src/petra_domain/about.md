In this layer, we create the heart of the app.
Here we define:
- Logs
- Anomalies
But **NOT** HOW we read or detect them, that will be in infra.

We are creating a inmutable, easy to test and reusable code, using
dataclases/pydantic for strong typing.

