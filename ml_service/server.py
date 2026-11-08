"""
FastAPI REST API Server for DDoS Detection Service
Provides HTTP endpoints for prediction, training, and mitigation
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from .config import settings
from .model import ModelManager, DDoSModel
from .faucet_client import FaucetClient, FlowStat, PortStat
from .grpc_service import DDoSServiceServicer

logger = logging.getLogger(__name__)

# Global instances
model_manager: Optional[ModelManager] = None
faucet_client: Optional[FaucetClient] = None
grpc_servicer: Optional[DDoSServiceServicer] = None
_start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global model_manager, faucet_client, grpc_servicer

    logger.info("Starting ML Service...")

    # Initialize components
    model_manager = ModelManager(Path(settings.model_dir))
    model_manager.load_all()

    faucet_client = FaucetClient()

    grpc_servicer = DDoSServiceServicer(model_manager, faucet_client)

    # Start background tasks
    asyncio.create_task(periodic_metrics_push())
    asyncio.create_task(auto_train_task())

    logger.info("ML Service started successfully")
    yield

    # Cleanup
    logger.info("Shutting down ML Service...")
    if faucet_client:
        await faucet_client.close()


app = FastAPI(
    title="DDoS Detection ML Service",
    description="ML-based DDoS detection with Faucet SDN integration",
    version=settings.model_version,
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class FlowFeature(BaseModel):
    timestamp: float = 0
    datapath_id: int = 0
    flow_id: str = ""
    ip_src: str = "0.0.0.0"
    tp_src: int = 0
    ip_dst: str = "0.0.0.0"
    tp_dst: int = 0
    ip_proto: int = 0
    icmp_code: int = 0
    icmp_type: int = 0
    flow_duration_sec: int = 0
    flow_duration_nsec: int = 0
    idle_timeout: int = 0
    hard_timeout: int = 0
    flags: int = 0
    packet_count: int = 0
    byte_count: int = 0
    packet_count_per_second: float = 0.0
    packet_count_per_nsecond: float = 0.0
    byte_count_per_second: float = 0.0
    byte_count_per_nsecond: float = 0.0


class FlowBatchRequest(BaseModel):
    flows: List[FlowFeature]
    switch_id: str = ""


class FlowPredictionResponse(BaseModel):
    flow_id: str
    label: int
    confidence: float
    switch_id: str


class PredictionResponse(BaseModel):
    predictions: List[FlowPredictionResponse]
    total_flows: int
    benign_count: int
    ddos_count: int
    ddos_percentage: float
    attack_detected: bool
    victim_host: str = ""
    timestamp: float


class TrainRequest(BaseModel):
    model_type: str = "RandomForest"
    params: Optional[Dict[str, str]] = None
    dataset_path: Optional[str] = None


class ModelInfoResponse(BaseModel):
    model_type: str
    version: str
    accuracy: float
    n_features: int
    params: Dict[str, Any]  # Accept any JSON-serializable params
    trained_at: str


class MitigationRequest(BaseModel):
    action: str  # "BLOCK_PORT", "UNBLOCK_PORT", "RATE_LIMIT"
    switch_id: str
    port_number: int
    reason: str = ""
    duration_seconds: int = 0


class MitigationResponse(BaseModel):
    success: bool
    action_id: str
    error: str = ""


class HealthResponse(BaseModel):
    healthy: bool
    version: str
    model_loaded: bool
    uptime: float


class ReadinessResponse(BaseModel):
    ready: bool
    model_loaded: bool
    telemetry_connected: bool


# API Endpoints
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint - process health only"""
    return HealthResponse(
        healthy=True,
        version=settings.model_version,
        model_loaded=model_manager.current_model is not None if model_manager else False,
        uptime=time.time() - _start_time
    )


@app.get("/ready", response_model=ReadinessResponse)
async def readiness_check():
    """Readiness check - model and telemetry status"""
    telemetry_ok = False
    if faucet_client:
        try:
            status = await faucet_client.get_switch_status()
            telemetry_ok = status.get("status") == "ok"
        except Exception:
            pass

    return ReadinessResponse(
        ready=model_manager.current_model is not None and telemetry_ok,
        model_loaded=model_manager.current_model is not None if model_manager else False,
        telemetry_connected=telemetry_ok
    )


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: FlowBatchRequest):
    """Predict flow labels via REST API"""
    if not model_manager or not model_manager.current_model:
        raise HTTPException(status_code=503, detail="No model loaded")

    try:
        import pandas as pd

        # Convert to DataFrame
        flows = [f.model_dump() for f in request.flows]
        df = pd.DataFrame(flows)

        # Predict
        labels, confidences = model_manager.predict(df)

        # Build response
        predictions = []
        benign = 0
        ddos = 0

        for i, (label, conf) in enumerate(zip(labels, confidences)):
            pred = FlowPredictionResponse(
                flow_id=flows[i].get('flow_id', f'flow_{i}'),
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
            for i, label in enumerate(labels):
                if label == 1:
                    dst = flows[i].get('ip_dst', '0.0.0.0')
                    try:
                        victim = f"h{int(dst.split('.')[-1])}"
                    except:
                        victim = "h1"
                    break

        # Record metrics
        if faucet_client:
            faucet_client.record_prediction(ddos > 0, request.switch_id, victim)

        return PredictionResponse(
            predictions=predictions,
            total_flows=total,
            benign_count=benign,
            ddos_count=ddos,
            ddos_percentage=ddos_pct,
            attack_detected=attack_detected,
            victim_host=victim,
            timestamp=time.time()
        )

    except HTTPException:
        raise  # Re-raise HTTPException as-is
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/train", response_model=ModelInfoResponse)
async def train(request: TrainRequest, background_tasks: BackgroundTasks):
    """Train a new model"""
    if not model_manager:
        raise HTTPException(status_code=503, detail="Model manager not initialized")

    try:
        # Run training in background
        background_tasks.add_task(train_model_background, request)

        return ModelInfoResponse(
            model_type=request.model_type,
            version=settings.model_version,
            accuracy=0.0,
            n_features=0,
            params={},
            trained_at=datetime.now().isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def train_model_background(request: TrainRequest):
    """Background training task"""
    import pandas as pd

    try:
        dataset_path = request.dataset_path or settings.dataset_path
        df = pd.read_csv(dataset_path)

        metadata = model_manager.train_model(request.model_type, df)

        logger.info(f"Background training completed: {metadata}")
    except Exception as e:
        logger.error(f"Background training failed: {e}")


@app.get("/model", response_model=ModelInfoResponse)
async def get_model_info():
    """Get current model info"""
    if not model_manager or not model_manager.current_model:
        raise HTTPException(status_code=404, detail="No model loaded")

    model = model_manager.current_model
    return ModelInfoResponse(
        model_type=model.model_type,
        version=settings.model_version,
        accuracy=model.accuracy,
        n_features=len(model.feature_columns),
        params=model.metadata.get('params', {}),
        trained_at=model.metadata.get('trained_at', '')
    )


@app.get("/models")
async def list_models():
    """List all available models"""
    if not model_manager:
        raise HTTPException(status_code=503, detail="Model manager not initialized")

    return model_manager.list_models()


@app.post("/model/{model_type}/activate")
async def activate_model(model_type: str):
    """Set active model"""
    if not model_manager:
        raise HTTPException(status_code=503, detail="Model manager not initialized")

    try:
        model_manager.set_current(model_type)
        return {"success": True, "model_type": model_type}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/mitigate", response_model=MitigationResponse)
async def mitigate(request: MitigationRequest):
    """Apply mitigation action"""
    if not faucet_client:
        raise HTTPException(status_code=503, detail="Faucet client not initialized")

    try:
        action_map = {
            "BLOCK_PORT": "BLOCK_PORT",
            "UNBLOCK_PORT": "UNBLOCK_PORT",
            "RATE_LIMIT": "RATE_LIMIT"
        }

        action = action_map.get(request.action.upper())
        if not action:
            raise HTTPException(status_code=400, detail=f"Invalid action: {request.action}")

        success = False

        if action == "BLOCK_PORT":
            success = await faucet_client.apply_acl(request.switch_id, request.port_number, block=True)
        elif action == "UNBLOCK_PORT":
            success = await faucet_client.apply_acl(request.switch_id, request.port_number, block=False)
        elif action == "RATE_LIMIT":
            # Rate limit implementation
            success = True  # Placeholder

        action_id = f"mit_{int(time.time())}_{request.switch_id}_{request.port_number}"

        if faucet_client:
            faucet_client.record_mitigation(action, request.switch_id, success)

        return MitigationResponse(
            success=success,
            action_id=action_id,
            error="" if success else "Mitigation failed"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mitigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats/flows")
async def get_flow_stats():
    """Get flow statistics from Faucet"""
    if not faucet_client:
        raise HTTPException(status_code=503, detail="Faucet client not initialized")

    try:
        flows = await faucet_client.get_flow_stats()
        return {"flows": [f.__dict__ for f in flows]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Flow stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats/ports")
async def get_port_stats():
    """Get port statistics from Faucet"""
    if not faucet_client:
        raise HTTPException(status_code=503, detail="Faucet client not initialized")

    try:
        ports = await faucet_client.get_port_stats()
        return {"ports": [p.__dict__ for p in ports]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Port stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats/switch")
async def get_switch_status():
    """Get switch status"""
    if not faucet_client:
        raise HTTPException(status_code=503, detail="Faucet client not initialized")

    try:
        status = await faucet_client.get_switch_status()
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Switch status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def get_metrics():
    """Get Prometheus metrics in text format"""
    if not faucet_client:
        raise HTTPException(status_code=503, detail="Faucet client not initialized")

    # Return metrics in Prometheus format
    metrics = faucet_client.get_metrics()
    return Response(content=metrics, media_type="text/plain; version=0.0.4; charset=utf-8")


# Background Tasks
async def periodic_metrics_push():
    """Periodically push metrics to Prometheus Pushgateway"""
    while True:
        try:
            await asyncio.sleep(60)  # Every minute
            if faucet_client:
                faucet_client.push_metrics()
        except Exception as e:
            logger.error(f"Metrics push error: {e}")


async def auto_train_task():
    """Auto-train model on startup if no model exists"""
    await asyncio.sleep(5)  # Wait for startup

    try:
        if model_manager and not model_manager.current_model:
            import pandas as pd
            import os

            if os.path.exists(settings.dataset_path):
                logger.info("Auto-training default model...")
                df = pd.read_csv(settings.dataset_path)
                model_manager.train_model(settings.default_model, df)
                logger.info("Auto-training completed")
    except Exception as e:
        logger.error(f"Auto-train error: {e}")


def run_server():
    """Run the FastAPI server"""
    uvicorn.run(
        "ml_service.server:app",
        host=settings.service_host,
        port=settings.service_port,
        log_level=settings.log_level.lower(),
        reload=False
    )


if __name__ == "__main__":
    run_server()