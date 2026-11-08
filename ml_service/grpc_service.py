"""
gRPC Service Implementation for DDoS Detection
"""

import asyncio
import logging
import time
from typing import AsyncIterator
from datetime import datetime

import grpc
import pandas as pd
from google.protobuf import empty_pb2

from .config import settings
from .model import ModelManager, DDoSModel
from .faucet_client import FaucetClient, FaucetConfigManager, FlowStat

# Import generated gRPC classes
# These will be generated from ddos.proto
try:
    import ddos_pb2
    import ddos_pb2_grpc
except ImportError:
    # Generate with: python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. ddos.proto
    ddos_pb2 = None
    ddos_pb2_grpc = None

logger = logging.getLogger(__name__)


class DDoSServiceServicer:
    """gRPC service implementation"""

    def __init__(self, model_manager: ModelManager, faucet_client: FaucetClient):
        self.model_manager = model_manager
        self.faucet_client = faucet_client
        self.config_manager = FaucetConfigManager()
        self.start_time = time.time()

        # Mitigation tracking
        self.mitigation_history = []
        self.last_mitigation = {}

    async def Predict(self, request, context):
        """Predict flow labels"""
        start = time.time()

        if ddos_pb2 is None:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("gRPC not available - protobuf not generated")
            return ddos_pb2.PredictionResponse() if ddos_pb2 else None

        try:
            # Convert gRPC request to DataFrame
            flows = []
            for flow in request.flows:
                flows.append({
                    'timestamp': flow.timestamp,
                    'datapath_id': flow.datapath_id,
                    'flow_id': flow.flow_id,
                    'ip_src': flow.ip_src,
                    'tp_src': flow.tp_src,
                    'ip_dst': flow.ip_dst,
                    'tp_dst': flow.tp_dst,
                    'ip_proto': flow.ip_proto,
                    'icmp_code': flow.icmp_code,
                    'icmp_type': flow.icmp_type,
                    'flow_duration_sec': flow.flow_duration_sec,
                    'flow_duration_nsec': flow.flow_duration_nsec,
                    'idle_timeout': flow.idle_timeout,
                    'hard_timeout': flow.hard_timeout,
                    'flags': flow.flags,
                    'packet_count': flow.packet_count,
                    'byte_count': flow.byte_count,
                    'packet_count_per_second': flow.packet_count_per_second,
                    'packet_count_per_nsecond': flow.packet_count_per_nsecond,
                    'byte_count_per_second': flow.byte_count_per_second,
                    'byte_count_per_nsecond': flow.byte_count_per_nsecond,
                })

            df = pd.DataFrame(flows)

            # Predict
            labels, confidences = self.model_manager.predict(df)

            # Build response
            predictions = []
            benign = 0
            ddos = 0

            for i, (label, conf) in enumerate(zip(labels, confidences)):
                pred = ddos_pb2.FlowPrediction(
                    flow_id=flows[i]['flow_id'],
                    label=int(label),
                    confidence=float(conf),
                    switch_id=request.switch_id
                )
                predictions.append(pred)

                if label == 1:
                    ddos += 1
                else:
                    benign += 1

            total = len(labels)
            ddos_pct = (ddos / total * 100) if total > 0 else 0
            attack_detected = ddos_pct > settings.ddos_threshold_percent

            # Determine victim
            victim = ""
            if attack_detected:
                # Find victim from DDoS flows
                for i, label in enumerate(labels):
                    if label == 1:
                        # Extract victim from ip_dst
                        dst = flows[i]['ip_dst']
                        try:
                            victim = f"h{int(dst.split('.')[-1])}"
                        except:
                            victim = "h1"
                        break

            # Record metrics
            latency = time.time() - start
            self.faucet_client.record_latency(latency)
            self.faucet_client.record_prediction(ddos > 0, request.switch_id, victim)

            return ddos_pb2.PredictionResponse(
                predictions=predictions,
                total_flows=total,
                benign_count=benign,
                ddos_count=ddos,
                ddos_percentage=ddos_pct,
                attack_detected=attack_detected,
                victim_host=victim,
                timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return ddos_pb2.PredictionResponse()

    async def Train(self, request, context):
        """Train a new model"""
        if ddos_pb2 is None:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("gRPC not available - protobuf not generated")
            return

        try:
            # Load dataset
            dataset_path = request.dataset_path or settings.dataset_path

            # Try to load existing data
            try:
                df = pd.read_csv(dataset_path)
            except FileNotFoundError:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Dataset not found: {dataset_path}")
                return ddos_pb2.TrainResponse(success=False, error="Dataset not found")

            # Train model
            metadata = self.model_manager.train_model(request.model_type, df)

            model_info = ddos_pb2.ModelInfo(
                model_type=metadata['model_type'],
                version=settings.model_version,
                accuracy=metadata['accuracy'],
                n_features=metadata['n_features'],
                params=metadata['params'],
                trained_at=metadata['trained_at']
            )

            return ddos_pb2.TrainResponse(
                success=True,
                model_info=model_info
            )

        except Exception as e:
            logger.error(f"Training error: {e}")
            return ddos_pb2.TrainResponse(success=False, error=str(e))

    async def GetModelInfo(self, request, context):
        """Get current model info"""
        if ddos_pb2 is None:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("gRPC not available - protobuf not generated")
            return

        if self.model_manager.current_model is None:
            return ddos_pb2.ModelInfo(
                model_type="None",
                version="0",
                accuracy=0.0
            )

        model = self.model_manager.current_model
        return ddos_pb2.ModelInfo(
            model_type=model.model_type,
            version=settings.model_version,
            accuracy=model.accuracy,
            n_features=len(model.feature_columns),
            params=model.metadata.get('params', {}),
            trained_at=model.metadata.get('trained_at', '')
        )

    async def Mitigate(self, request, context):
        """Apply mitigation action"""
        if ddos_pb2 is None:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("gRPC not available - protobuf not generated")
            return

        try:
            action_id = f"mit_{int(time.time())}_{request.switch_id}_{request.port_number}"

            # Check cooldown
            key = f"{request.switch_id}:{request.port_number}"
            if key in self.last_mitigation:
                elapsed = time.time() - self.last_mitigation[key]
                if elapsed < settings.mitigation_cooldown:
                    return ddos_pb2.MitigationResponse(
                        success=False,
                        action_id=action_id,
                        error=f"Cooldown active, wait {settings.mitigation_cooldown - elapsed:.0f}s"
                    )

            success = False

            if request.action == ddos_pb2.MitigationAction.ActionType.BLOCK_PORT:
                success = await self.faucet_client.apply_acl(
                    request.switch_id,
                    request.port_number,
                    block=True
                )
                if success:
                    self.last_mitigation[key] = time.time()

            elif request.action == ddos_pb2.MitigationAction.ActionType.UNBLOCK_PORT:
                success = await self.faucet_client.apply_acl(
                    request.switch_id,
                    request.port_number,
                    block=False
                )
                if success and key in self.last_mitigation:
                    del self.last_mitigation[key]

            elif request.action == ddos_pb2.MitigationAction.ActionType.RATE_LIMIT:
                # Rate limiting via Faucet meters
                success = await self._apply_rate_limit(request)

            # Record history
            self.mitigation_history.append({
                'action_id': action_id,
                'action': ddos_pb2.MitigationAction.ActionType.Name(request.action),
                'switch': request.switch_id,
                'port': request.port_number,
                'reason': request.reason,
                'duration': request.duration_seconds,
                'success': success,
                'timestamp': time.time()
            })

            self.faucet_client.record_mitigation(
                ddos_pb2.MitigationAction.ActionType.Name(request.action),
                request.switch_id,
                success
            )

            return ddos_pb2.MitigationResponse(
                success=success,
                action_id=action_id
            )

        except Exception as e:
            logger.error(f"Mitigation error: {e}")
            return ddos_pb2.MitigationResponse(success=False, error=str(e))

    async def _apply_rate_limit(self, request) -> bool:
        """Apply rate limit via Faucet meter"""
        # This would configure Faucet meters on the switch
        # For now, return True as placeholder
        # In production, this would add a meter to the ACL rule
        logger.warning(f"Rate limiting not fully implemented for {request.switch_id}:{request.port_number}")
        return True

    async def Health(self, request, context):
        """Health check"""
        if ddos_pb2 is None:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("gRPC not available - protobuf not generated")
            return

        return ddos_pb2.HealthResponse(
            healthy=True,
            version=settings.model_version,
            model_loaded=self.model_manager.current_model is not None,
            uptime=time.time() - self.start_time
        )


async def serve(model_manager: ModelManager, faucet_client: FaucetClient):
    """Start gRPC server"""
    if ddos_pb2_grpc is None:
        logger.error("gRPC not available - protobuf not generated. Run: python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. ddos.proto")
        return

    server = grpc.aio.server()
    servicer = DDoSServiceServicer(model_manager, faucet_client)

    ddos_pb2_grpc.add_DDoSServiceServicer_to_server(servicer, server)

    listen_addr = f"[::]:{settings.grpc_port}"
    server.add_insecure_port(listen_addr)

    logger.info(f"Starting gRPC server on {listen_addr}")
    await server.start()

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        await server.stop(5)
        await faucet_client.close()